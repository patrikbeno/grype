package cmd

import (
	"fmt"
	"github.com/anchore/grype/grype/matcher/ossi"
	"github.com/anchore/grype/internal/log"
	"io/ioutil"
	"path"

	"github.com/spf13/cobra"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/grype/grype/db"
	"github.com/anchore/grype/grype/event"
	"github.com/anchore/grype/internal/bus"
	"github.com/anchore/grype/internal/ui"
	"github.com/anchore/stereoscope"
)

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "download the latest vulnerability database",
	Args:  cobra.ExactArgs(0),
	RunE:  runDBUpdateCmd,
}

func init() {
	dbCmd.AddCommand(dbUpdateCmd)
}

func startDBUpdateCmd() <-chan error {

	runOssiUpdate()

	errs := make(chan error)
	go func() {
		defer close(errs)
		dbCurator, err := db.NewCurator(appConfig.DB.ToCuratorConfig())
		if err != nil {
			errs <- err
			return
		}
		updated, err := dbCurator.Update()
		if err != nil {
			errs <- fmt.Errorf("unable to update vulnerability database: %+v", err)
		}

		result := "No vulnerability database update available\n"
		if updated {
			result = "Vulnerability database updated!\n"
		}

		bus.Publish(partybus.Event{
			Type:  event.NonRootCommandFinished,
			Value: result,
		})
	}()
	return errs
}

func runDBUpdateCmd(_ *cobra.Command, _ []string) error {
	reporter, closer, err := reportWriter()
	defer func() {
		if err := closer(); err != nil {
			log.Warnf("unable to write to report destination: %+v", err)
		}
	}()
	if err != nil {
		return err
	}
	return eventLoop(
		startDBUpdateCmd(),
		setupSignals(),
		eventSubscription,
		stereoscope.Cleanup,
		ui.Select(isVerbose(), appConfig.Quiet, reporter)...,
	)
}

func runOssiUpdate() {
	var coordinates []string
	dir := path.Join(".workspace", "ossi", "pkg")
	types, _ := ioutil.ReadDir(dir)
	for _, t := range types {
		if !t.IsDir() {
			continue
		}
		namespaces, _ := ioutil.ReadDir(path.Join(dir, t.Name()))
		for _, ns := range namespaces {
			if !ns.IsDir() {
				continue
			}
			names, _ := ioutil.ReadDir(path.Join(dir, t.Name(), ns.Name()))
			for _, n := range names {
				if !n.IsDir() {
					continue
				}
				versions, _ := ioutil.ReadDir(path.Join(dir, t.Name(), ns.Name(), n.Name()))
				for _, v := range versions {
					if !v.IsDir() {
						continue
					}
					//fname := path.Join(dir, t.Name(), ns.Name(), n.Name(), v.Name(), "ossi.json")
					purl := fmt.Sprintf("pkg:%s/%s/%s@%s", t.Name(), ns.Name(), n.Name(), v.Name())
					coordinates = append(coordinates, purl)
				}
			}
		}
	}
	log.Infof("Found %d cached component reports. Updating all...", len(coordinates))
	m := ossi.NewOssiMatcher()
	m.LoadReports(coordinates)
}
