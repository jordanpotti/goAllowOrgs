# goAllowOrgs
A Golang tool to whitelist ASN's based on organization name. This works by providing a list of ASN org names. This tool uses goPacket to monitor incoming traffic, capturing the IP's and cheking the IP to see if it is a part of a whitelisted ASN. If it is not, it blocks that connection and future connections using iptables.

## Uses
- Whitelisting common ISP and target ASN's which in turn blocks connections from data centers.. think security tools..
- Can be ran on any host, doesn't require a proxy or anything since its simply a packet sniffer

## Disclaimers
- This tool is fairly janky, since it blocks the traffic after the IP connects, the first few packets may get through. Not a problem if you have SSL since the SSL handshake takes enough time to drop the connections. If it is one web page with port 80, the page may be returned in cases where this tool does not kill the connection fast enough. 



## Getting Started

#### Pull ASN data from db-ip, various libraries and add required headers
```
sudo apt-get install libpcap-dev
curl https://download.db-ip.com/free/dbip-asn-lite-2021-06.csv.gz -o asndata.csv.gz
gunzip asndata.csv.gz
sed -i '1 i\first,last,asn,org_name' asndata.csv
curl -fsSL https://github.com/banviktor/asnlookup/releases/download/v0.1.0/asnlookup-linux-amd64-v0.1.0.tar.gz | sudo tar -zx 
curl https://raw.githubusercontent.com/banviktor/asnlookup/main/hack/pull_rib.sh -o pull_rib.sh
chmod +x pull_rib.sh
./pull_rib.sh
bzcat rib.*.bz2 | ./asnlookup-utils convert --input - --output asn.db
touch allowed_orgs.txt
```

#### Now populate the allowed_orgs.txt file with line delimited strings of allowed orgs, example:
````
att
verizon
charter
spectrum
````

#### Now you should be ready to run the tool

````
root@ip-10-10-90-48:/home/jordan/test# ./main -h
                  _  _
 __ _  ___  __ _ | || | ___ __ __ __ ___  _ _  __ _
/ _` |/ _ \/ _` || || |/ _ \\ V  V // _ \| '_|/ _` |
\__, |\___/\__,_||_||_|\___/ \_/\_/ \___/|_|  \__, |
|___/                                         |___/
Usage of ./main:
  -asn_csv string
        CSV file with org name to ASN number (default "asndata.csv")
  -asn_db string
        ASN database (default "asn.db")
  -interface string
        Interface name (default "ens5")
  -orgs string
        File with line delimited orgs to allow (default "allowed_orgs.txt")
  -output string
        Log file name (default "goFW.log")
  -port string
        Port to monitor (default "443")
````



