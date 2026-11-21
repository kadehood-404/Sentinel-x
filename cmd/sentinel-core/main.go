// sentinel-core: offline tools for rulebooks and the audit ledger.
//
//	sentinel-core lint <rules-dir>       validate a rulebook and list its rules
//	sentinel-core verify <ledger-file>   check the ledger's hash chain
package main

import (
	"fmt"
	"os"

	"github.com/kadehood-404/sentinel-x/internal/ledger"
	"github.com/kadehood-404/sentinel-x/internal/policy"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: sentinel-core lint <rules-dir> | verify <ledger-file>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "lint":
		rs, err := policy.Load(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			os.Exit(1)
		}
		fmt.Printf("OK: %d rules (version %s)\n", len(rs.Rules), rs.Signature)
		for _, r := range rs.Rules {
			fmt.Printf("  %-26s %-9s %-11s %s\n", r.ID, r.Target, r.Action, r.Severity)
		}
	case "verify":
		n, err := ledger.Verify(os.Args[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "TAMPERED OR CORRUPT after %d good records: %v\n", n, err)
			os.Exit(1)
		}
		fmt.Printf("OK: %d records, chain intact\n", n)
	default:
		fmt.Fprintln(os.Stderr, "unknown command", os.Args[1])
		os.Exit(2)
	}
}
