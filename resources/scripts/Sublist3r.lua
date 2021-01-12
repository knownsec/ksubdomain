-- Copyright 2017 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Sublist3rAPI" -- * 插件名称(必须)
type = "api" -- 插件类型(不必须)

local json = require("json")

function buildurl(domain)
    return "https://api.sublist3r.com/search.php?domain=" .. domain
end

-- 需要实现一个vertical函数，返回类型为一个域名的table，如果失败可以返回nil
function vertical(domain)
    local page, err = request({url=buildurl(domain)})
    if (err ~= nil and err ~= "") then
        return
    end
    local resp = json.decode(page)
    if (resp == nil or #resp == 0) then
        return
    end
    local a = {}
    for i, v in pairs(resp) do
        table.insert(a, v)
    end
    return a
end

