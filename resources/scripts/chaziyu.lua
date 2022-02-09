--
-- Copyright 2021 w8ay. All rights reserved.

name = "chaziyu"
type = "api"

function vertical(domain)
    return scrape({url=buildurl(domain)},domain)
end

function buildurl(domain)
    return "https://chaziyu.com/" .. domain .. "/"
end
