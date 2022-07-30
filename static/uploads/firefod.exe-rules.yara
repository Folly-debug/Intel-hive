alert dns $HOME_NET any -> $EXTERNAL_NET 53 (msg:"Unkown RAT traffic detected"; dns_query; content:"aaaaaaaaaaaaaaaaaaaa.kadusus.local"; nocase; classtype:command-and-control; sid:10000000; rev:1;)
