package utils

import (
	"reflect"
	"testing"
)

// Assuming LoadNetworkData is defined in your main code.
// Assuming networks is your hardcoded map.

func TestLoadNetworkData(t *testing.T) {
	networks = defaultNetworkData
	// Mock JSON string that should match your hardcoded map
	// Replace this with your actual JSON data as a string
	jsonStr := exampleNeoFSStatusData

	// Call your function to load data from the JSON string
	generatedMap, err := LoadNetworkData([]byte(jsonStr))
	if err != nil {
		t.Fatalf("Failed to load network data: %v", err)
	}

	// Now compare generatedMap with your hardcoded map `networks`
	for network, data := range networks {
		generatedData, exists := generatedMap[network]
		if !exists {
			t.Errorf("Network %s does not exist in generated map", network)
			continue
		}

		// Compare Name, ID, Address, etc.
		if data.Name != generatedData.Name {
			t.Errorf("Name mismatch for %s: got %s, want %s", network, generatedData.Name, data.Name)
		}
		if data.ID != generatedData.ID {
			t.Errorf("ID mismatch for %s: got %s, want %s", network, generatedData.ID, data.ID)
		}
		if data.Address != generatedData.Address {
			t.Errorf("Address mismatch for %s: got %s, want %s", network, generatedData.Address, data.Address)
		}

		// Extend this to compare other fields, including slices and maps
		// For slices and maps, you might want to use reflect.DeepEqual
		if !reflect.DeepEqual(data.SidechainRPC, generatedData.SidechainRPC) {
			t.Errorf("SidechainRPC mismatch for %s", network)
		}
		if !reflect.DeepEqual(data.StorageNodes, generatedData.StorageNodes) {
			t.Errorf("StorageNodes mismatch for %s - %v - %v", network, data.StorageNodes, generatedData.StorageNodes)
		}
		if !reflect.DeepEqual(data.RpcNodes, generatedData.RpcNodes) {
			t.Errorf("RpcNodes mismatch for %s", network)
		}
	}
}

var exampleNeoFSStatusData = `{
    "status": {
        "mainnet": "Healthy",
        "testnet": "Healthy"
    },
    "statusmsgs": {
        "mainnet": [],
        "testnet": []
    },
    "network_epoch": {
        "mainnet": 21933.0,
        "testnet": 12739.0
    },
    "containers": {
        "mainnet": 55.0,
        "testnet": 200.0
    },
    "time": 1710328220.8687477,
    "node_map": [
        {
            "latitude": "50.4667",
            "location": "Falkenstein",
            "longitude": "12.3833",
            "nodes": [
                {
                    "net": "main",
                    "value": 2.0
                }
            ]
        },
        {
            "latitude": "59.9333",
            "location": "Vassilevsky Ostrov/St Petersburg",
            "longitude": "30.2167",
            "nodes": [
                {
                    "net": "main",
                    "value": 1.0
                }
            ]
        },
        {
            "latitude": "60.4000",
            "location": "Tuusula",
            "longitude": "25.0333",
            "nodes": [
                {
                    "net": "main",
                    "value": 2.0
                }
            ]
        },
        {
            "latitude": "1.4169",
            "location": "Singapore",
            "longitude": "103.8680",
            "nodes": [
                {
                    "net": "test",
                    "value": 1.0
                }
            ]
        },
        {
            "latitude": "37.6190",
            "location": "San Francisco",
            "longitude": "-122.3750",
            "nodes": [
                {
                    "net": "test",
                    "value": 1.0
                }
            ]
        },
        {
            "latitude": "50.1167",
            "location": "Frankfurt am Main",
            "longitude": "8.6833",
            "nodes": [
                {
                    "net": "test",
                    "value": 1.0
                }
            ]
        },
        {
            "latitude": "52.4000",
            "location": "Amsterdam",
            "longitude": "4.8167",
            "nodes": [
                {
                    "net": "test",
                    "value": 1.0
                }
            ]
        }
    ],
    "contract": {
        "mainnet": {
            "address": "NNxVrKjLsRkWsmGgmuNXLcMswtxTGaNQLk",
            "script_hash": "2cafa46838e8b564468ebd868dcafdd99dce6221"
        },
        "testnet": {
            "address": "NZAUkYbJ1Cb2HrNmwZ1pg9xYHBhm2FgtKV",
            "script_hash": "3c3f4b84773ef0141576e48c3ff60e5078235891"
        }
    },
    "gateways": {
        "mainnet": [
            [
                "https://http.fs.neo.org",
                "https://rest.fs.neo.org/v1"
            ]
        ],
        "testnet": [
            [
                "https://http.t5.fs.neo.org",
                "https://rest.t5.fs.neo.org/v1"
            ]
        ]
    },
    "side_chain_rpc_nodes": {
        "mainnet": [
            [
                "https://rpc1.morph.fs.neo.org:40341",
                "wss://rpc1.morph.fs.neo.org:40341/ws"
            ],
            [
                "https://rpc2.morph.fs.neo.org:40341",
                "wss://rpc2.morph.fs.neo.org:40341/ws"
            ],
            [
                "https://rpc3.morph.fs.neo.org:40341",
                "wss://rpc3.morph.fs.neo.org:40341/ws"
            ],
            [
                "https://rpc4.morph.fs.neo.org:40341",
                "wss://rpc4.morph.fs.neo.org:40341/ws"
            ],
            [
                "https://rpc5.morph.fs.neo.org:40341",
                "wss://rpc5.morph.fs.neo.org:40341/ws"
            ],
            [
                "https://rpc6.morph.fs.neo.org:40341",
                "wss://rpc6.morph.fs.neo.org:40341/ws"
            ],
            [
                "https://rpc7.morph.fs.neo.org:40341",
                "wss://rpc7.morph.fs.neo.org:40341/ws"
            ]
        ],
        "testnet": [
            [
                "https://rpc1.morph.t5.fs.neo.org:51331",
                "wss://rpc1.morph.t5.fs.neo.org:51331/ws"
            ],
            [
                "https://rpc2.morph.t5.fs.neo.org:51331",
                "wss://rpc2.morph.t5.fs.neo.org:51331/ws"
            ],
            [
                "https://rpc3.morph.t5.fs.neo.org:51331",
                "wss://rpc3.morph.t5.fs.neo.org:51331/ws"
            ],
            [
                "https://rpc4.morph.t5.fs.neo.org:51331",
                "wss://rpc4.morph.t5.fs.neo.org:51331/ws"
            ],
            [
                "https://rpc5.morph.t5.fs.neo.org:51331",
                "wss://rpc5.morph.t5.fs.neo.org:51331/ws"
            ],
            [
                "https://rpc6.morph.t5.fs.neo.org:51331",
                "wss://rpc6.morph.t5.fs.neo.org:51331/ws"
            ],
            [
                "https://rpc7.morph.t5.fs.neo.org:51331",
                "wss://rpc7.morph.t5.fs.neo.org:51331/ws"
            ]
        ]
    },
    "storage_nodes": {
        "mainnet": [
            [
                "grpcs://st1.storage.fs.neo.org:8082",
                "st1.storage.fs.neo.org:8080"
            ],
            [
                "grpcs://st2.storage.fs.neo.org:8082",
                "st2.storage.fs.neo.org:8080"
            ],
            [
                "grpcs://st3.storage.fs.neo.org:8082",
                "st3.storage.fs.neo.org:8080"
            ],
            [
                "grpcs://st4.storage.fs.neo.org:8082",
                "st4.storage.fs.neo.org:8080"
            ]
        ],
        "testnet": [
            [
                "grpcs://st1.t5.fs.neo.org:8082",
                "st1.t5.fs.neo.org:8080"
            ],
            [
                "grpcs://st2.t5.fs.neo.org:8082",
                "st2.t5.fs.neo.org:8080"
            ],
            [
                "grpcs://st3.t5.fs.neo.org:8082",
                "st3.t5.fs.neo.org:8080"
            ],
            [
                "grpcs://st4.t5.fs.neo.org:8082",
                "st4.t5.fs.neo.org:8080"
            ]
        ]
    },
    "neo_go_rpc_nodes": {
        "mainnet": [
            [
                "https://rpc10.n3.nspcc.ru:10331",
                "wss://rpc10.n3.nspcc.ru:10331/ws"
            ]
        ],
        "testnet": [
            [
                "https://rpc.t5.n3.nspcc.ru:20331",
                "wss://rpc.t5.n3.nspcc.ru:20331/ws"
            ]
        ]
    }
}`
