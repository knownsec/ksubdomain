--
-- Copyright 2021 w8ay. All rights reserved.

name = "chinaz"
type = "api"

function vertical(domain)
    return scrape({url=buildurl(domain)},domain)
end

function buildurl(domain)
    return "https://alexa.chinaz.com/" .. domain
end