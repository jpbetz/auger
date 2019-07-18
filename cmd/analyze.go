package cmd

import (
	"fmt"
	"sort"

	"github.com/jpbetz/auger/pkg/data"
	"github.com/spf13/cobra"
)

var analyzeCmd = &cobra.Command{
	Use:   "analyze",
	Short: "Analyze kubernetes data from the boltdb '.db' files etcd persists to.",
	RunE: func(cmd *cobra.Command, args []string) error {
		return analyzeValidateAndRun()
	},
}

type analyzeOptions struct {
	filename string
}

var analyzeOpts *analyzeOptions = &analyzeOptions{}

func init() {
	RootCmd.AddCommand(analyzeCmd)
	analyzeCmd.Flags().StringVarP(&analyzeOpts.filename, "file", "f", "", "Bolt DB '.db' filename")
}

func analyzeValidateAndRun() error {
	summaries, err := data.ListKeySummaries(analyzeOpts.filename, []data.Filter{}, &data.KeySummaryProjection{HasKey: true, HasValue: false}, 0)
	if err != nil {
		return err
	}

	objectCounts := map[string]uint{}
	for _, s := range summaries {
		if s.TypeMeta != nil {
			objectCounts[fmt.Sprintf("%s/%s", s.TypeMeta.APIVersion, s.TypeMeta.Kind)] += 1
		}
	}

	type entry struct {
		count uint
		gvk   string
	}

	entries := []entry{}
	for k, v := range objectCounts {
		entries = append(entries, entry{gvk: k, count: v})
	}

	sort.Slice(entries[:], func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

	var totalKeySize int
	var totalValueSize int
	var totalAllVersionsKeySize int
	var totalAllVersionsValueSize int
	for _, summary := range summaries {
		totalKeySize += summary.Stats.KeySize
		totalValueSize += summary.Stats.ValueSize
		totalAllVersionsKeySize += summary.Stats.AllVersionsKeySize
		totalAllVersionsValueSize += summary.Stats.AllVersionsValueSize
	}

	fmt.Printf("Total kubernetes objects: %d\n", len(summaries))
	fmt.Printf("Total (all revisions) storage used by kubernetes objects: %d\n", totalAllVersionsKeySize+totalAllVersionsValueSize)
	fmt.Printf("Current (latest revision) storage used by kubernetes objects: %d\n", totalKeySize+totalValueSize)
	fmt.Printf("\n")
	fmt.Printf("Most common kubernetes types:\n")
	for i, entry := range entries {
		fmt.Printf("\t%d\t%s\n", entry.count, entry.gvk)
		if i > 10 {
			break
		}
	}

	sort.Slice(summaries[:], func(i, j int) bool {
		return summaries[i].Stats.AllVersionsValueSize > summaries[j].Stats.AllVersionsValueSize
	})
	fmt.Printf("\n")
	fmt.Printf("Largest objects (byte size sum of all revisions):\n")
	for i, summary := range summaries {
		fmt.Printf("\t%d\t%s (%s/%s)\n", summary.Stats.AllVersionsValueSize, summary.Key, summary.TypeMeta.APIVersion, summary.TypeMeta.Kind)
		if i > 10 {
			break
		}
	}

	return nil
}
