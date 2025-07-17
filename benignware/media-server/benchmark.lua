-- benchmark.lua for wrk
-- Reads list of URLs from a file and hits them with optional headers (e.g., auth)

-- CONFIG
local file_path   = "photoprism.url"     -- file with endpoints (one per line)
local auth_token  = os.getenv("TOKEN") -- set your token here, or pass via env

-- STATE
local urls = {}
local counter = 1

-- Called once before benchmarking starts
function setup(thread)
  -- load URLs from file
  for line in io.lines(file_path) do
    if #line > 0 then
      table.insert(urls, line)
    end
  end

  if #urls == 0 then
    error("No endpoints found in " .. file_path)
  end
end

-- Called for each request
function request()
  -- cycle through URLs (or math.random if you want random)
  local url = urls[counter]
  counter = counter + 1
  if counter > #urls then
    counter = 1
  end

  local headers = {
    ["X-Auth-Token"] = auth_token
  }

  return wrk.format("GET", url, headers, nil)
end

