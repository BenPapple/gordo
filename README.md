# Gordo Port Scanner
Basic port scanner for TCP.

# Flags
-a "enable all ports scan"

-h help

-t "set target IP/URL"

-v "enable verbose output"

-w "set worker count > 0"


# Use case
go run gordoportscanner.go -t 127.0.0.1

go run gordoportscanner.go -t URL
