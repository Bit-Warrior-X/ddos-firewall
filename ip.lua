math.randomseed(os.time())

request = function()
  local ip = string.format("%d.%d.%d.%d",
      math.random(1,255),
      math.random(0,255),
      math.random(0,255),
      math.random(1,255))
  wrk.headers["X-Forwarded-For"] = ip
  return wrk.format(nil, "/api")
end
