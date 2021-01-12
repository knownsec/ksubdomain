--
-- Copyright 2021 w8ay. All rights reserved.

name = "crt.sh"
type = "api"

function vertical(domain)
    return scrape({url=buildurl(domain)},domain)
end

function buildurl(domain)
    return "https://crt.sh/?output=json&q=" .. domain
end
