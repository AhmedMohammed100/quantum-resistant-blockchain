// Command manifestcheck exercises the independent v2 manifest validator with
// the repository's published fixture profiles. It is a conformance test tool,
// not a production node or network activation entry point.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/AhmedMohammed100/quantum-resistant-blockchain/conformance/go"
)

func main() {
	chainID := flag.String("chain-id", "", "locally configured expected chain ID")
	genesisHash := flag.String("genesis-hash", "", "locally configured expected genesis hash")
	flag.Parse()
	if *chainID == "" || *genesisHash == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "chain-id and genesis-hash are required; manifest is read from stdin")
		os.Exit(2)
	}

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	manifest, err := qbccjson.ParseCanonicalJSONV1(raw)
	if err != nil {
		fail(err)
	}
	digest, err := qbccjson.ValidateV2NetworkManifest(
		manifest,
		*chainID,
		*genesisHash,
		map[string]bool{"transfer": true},
		map[qbccjson.V2ManifestProfileKey]qbccjson.V2ManifestDescriptorValidator{
			{ID: "fixture_pq_v1", Version: "1.0.0"}: func(map[string]any) error { return nil },
		},
		map[qbccjson.V2ManifestProfileKey]qbccjson.V2ManifestDescriptorValidator{
			{ID: "fixture-pow", Version: "1"}: func(map[string]any) error { return nil },
		},
	)
	if err != nil {
		fail(err)
	}
	fmt.Println(digest)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
