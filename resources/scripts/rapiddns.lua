-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
--
-- Copyright 2021 w8ay. All rights reserved.
name = "RapidDNS"
type = "scrape"


function vertical( domain)
    return scrape({url=buildurl(domain)},domain)
end

function buildurl(domain)
    return "https://rapiddns.io/subdomain/" .. domain .. "?full=1"
end
