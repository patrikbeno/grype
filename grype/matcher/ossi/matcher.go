package ossi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/anchore/grype/grype/distro"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/log"
	"github.com/anchore/packageurl-go"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/nscuro/ossindex-client"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

type Matcher struct {
	*ossindex.Client
	Workspace string
}

func NewOssiMatcher() *Matcher {
	return &Matcher{
		Client:    NewOssiClient(),
		Workspace: path.Join(".workspace", "ossi"),
	}
}

func NewOssiClient() *ossindex.Client {
	c, err := ossindex.NewClient(ossindex.WithAuthentication("patrikbeno@gmail.com", "2c2cddc98819ce7db685ebb69fea9c9fd2724c6"))
	if err != nil {
		log.Warn("Failed to initialize OSSI client: %s", err)
	}
	return c
}

func (m Matcher) PackageTypes() []syftPkg.Type {
	return []syftPkg.Type{
		syftPkg.JavaPkg,
		syftPkg.NpmPkg,
		syftPkg.DotnetPkg,
		syftPkg.GoModulePkg,
	}
}

func (m Matcher) Type() match.MatcherType {
	return match.OssiMatcher
}

func (m Matcher) Match(provider vulnerability.Provider, distro *distro.Distro, p pkg.Package) ([]match.Match, error) {

	fname := m.fileName(p.PURL)
	data := loadFile(*fname)
	r := ossindex.ComponentReport{}
	json.Unmarshal(*data, &r)

	var matches []match.Match
	for _, v := range r.Vulnerabilities {
		matches = append(matches, match.Match{
			Package: p,
			Vulnerability: vulnerability.Vulnerability{
				ID:        v.ID,
				Namespace: "ossi",
				//Constraint: version.MustGetConstraint(v.VersionRanges[0], match.ExactDirectMatch),
				//Fix: vulnerability.Fix{
				//    Versions: nil,
				//    State:    "",
				//},
				Advisories: []vulnerability.Advisory{{
					ID:   "ossi",
					Link: r.Reference,
				}},
				RelatedVulnerabilities: nil,
			},
			Details: []match.Detail{
				{
					Type:    match.ExactDirectMatch,
					Matcher: match.OssiMatcher,
					SearchedBy: map[string]interface{}{
						"language":  string(p.Language),
						"namespace": "ossi",
					},
					Found: map[string]interface{}{
						"versionConstraint": v.VersionRanges,
					},
					Confidence: 1.0,
				},
			},
		})
	}
	return matches, nil
}

func (m *Matcher) Load(packages []pkg.Package) {
	var creating []string
	var updating []string
	cached := 0
	now := time.Now()
	min := now.Add(time.Duration(-5) * 24 * time.Hour)
	for _, p := range packages {

		// simplify purl
		x := p.PURL
		x, _, _ = strings.Cut(x, "?")

		fname := m.fileName(p.PURL)
		if !exists(*fname) {
			creating = append(creating, x)
		} else if lastModified(*fname).Before(min) {
			updating = append(updating, x)
		} else {
			cached++ //up to date
		}
	}

	log.Infof("OSSI: Loading vulnerability reports for %d components: %d new, %d updates, %d cached",
		len(packages), len(creating), len(updating), cached)

	m.LoadReports(creating)
	m.LoadReports(updating)
}

func (m *Matcher) fileName(spurl string) *string {
	purl, err := packageurl.FromString(spurl)
	if err != nil {
		return nil
	}
	fname := path.Join(m.Workspace, "pkg", purl.Type, purl.Namespace, purl.Name, purl.Version, "ossi.json")
	return &fname
}

func exists(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func lastModified(fname string) time.Time {
	f, err := os.Stat(fname)
	if err != nil {
		return time.Time{}
	}
	return f.ModTime()
}

func loadFile(fname string) *[]byte {
	data, err := ioutil.ReadFile(fname)
	if err != nil {
		return nil
	}
	return &data
}

func (m *Matcher) LoadReports(coordinates []string) {
	if len(coordinates) == 0 {
		return
	}
	reports, err := m.Client.GetComponentReports(context.Background(), coordinates)
	if err != nil {
		log.Warn("OSSI failure: %s", err)
		return
	}
	log.Debugf("Successfully loaded %d reports from OSSI", len(reports))
	for _, r := range reports {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			log.Warn("Error converting to JSON %s", err)
			continue
		}
		fpath := *m.fileName(r.Coordinates)
		_ = os.MkdirAll(filepath.Dir(fpath), 0755)
		err = ioutil.WriteFile(fpath, data, 0644)
		if err != nil {
			log.Warn("Error writing file: %s, error: %s", fpath, err)
		}
		log.Debugf("Saved %s", fpath)
	}

	// vulnerabilities index
	for _, r := range reports {
		for _, v := range r.Vulnerabilities {
			data, err := json.MarshalIndent(v, "", "  ")
			if err != nil {
				log.Warnf("Error converting to json: %s", v.ID)
				continue
			}
			fname := v.ID
			fname = strings.ReplaceAll(fname, "-", "/")
			fname = path.Join(m.Workspace, "vulns", fname, v.ID+".json")
			_ = os.MkdirAll(filepath.Dir(fname), 0755)
			err = ioutil.WriteFile(fname, data, 0644)
			if err != nil {
				log.Warnf("Error saving %s", fname)
				continue
			}
			log.Debugf("Saved %s", fname)
		}
	}
}
