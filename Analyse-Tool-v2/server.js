import express from "express"
import { spawn } from "child_process"
import { promisify } from "util"
import dns from "dns"
import net from "net"
import fs from "fs/promises"
import jwt from "jsonwebtoken"
import path from "path"
import { fileURLToPath } from "url"

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
const PORT = 3000
const JWT_SECRET = "modern-network-analyzer-secret-2024"

// Middleware
app.use(express.json())
app.use(express.static("public"))

// Enhanced user database with roles
const users = {
  admin: { password: "password123", role: "admin" },
  analyst: { password: "secure456", role: "analyst" },
  user: { password: "test123", role: "user" },
}

// Rate limiting
const rateLimiter = new Map()

const checkRateLimit = (req, res, next) => {
  const ip = req.ip
  const now = Date.now()
  const windowMs = 60 * 1000 // 1 minute
  const maxRequests = 10

  if (!rateLimiter.has(ip)) {
    rateLimiter.set(ip, { count: 1, resetTime: now + windowMs })
    return next()
  }

  const limit = rateLimiter.get(ip)
  if (now > limit.resetTime) {
    limit.count = 1
    limit.resetTime = now + windowMs
    return next()
  }

  if (limit.count >= maxRequests) {
    return res.status(429).json({
      success: false,
      message: "Too many requests. Please try again later.",
    })
  }

  limit.count++
  next()
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ success: false, message: "Access token required" })
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid token" })
    }
    req.user = user
    next()
  })
}

// Enhanced login endpoint
app.post("/api/login", checkRateLimit, (req, res) => {
  const { username, password } = req.body

  if (!username || !password) {
    return res.json({ success: false, message: "Username and password required" })
  }

  const user = users[username]
  if (user && user.password === password) {
    const token = jwt.sign({ username, role: user.role }, JWT_SECRET, { expiresIn: "24h" })
    res.json({
      success: true,
      token,
      user: { username, role: user.role },
    })
  } else {
    res.json({ success: false, message: "Invalid credentials" })
  }
})

// Enhanced IP geolocation with caching
const geoCache = new Map()

async function getIpInfo(ip) {
  if (geoCache.has(ip)) {
    return geoCache.get(ip)
  }

  try {
    const response = await fetch(
      `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,isp,as,lat,lon,timezone`
    )
    const data = await response.json()

    if (data.status === "success") {
      const result = {
        Country: data.country,
        Region: data.regionName,
        City: data.city,
        ISP: data.isp,
        ASN: data.as,
        Latitude: data.lat,
        Longitude: data.lon,
        Timezone: data.timezone,
      }
      geoCache.set(ip, result)
      return result
    }
    return null
  } catch (error) {
    console.error(`GeoIP lookup failed for ${ip}:`, error.message)
    return null
  }
}

// Enhanced reverse DNS lookup
async function reverseDnsLookup(ip) {
  try {
    const lookupAsync = promisify(dns.reverse)
    const hostnames = await lookupAsync(ip)
    return hostnames[0] || "No PTR record found"
  } catch (error) {
    return "No PTR record found"
  }
}

// Enhanced ping with more detailed stats
async function pingHost(ip) {
  return new Promise((resolve) => {
    const isWindows = process.platform === "win32"
    const cmd = isWindows ? "ping" : "ping"
    const args = isWindows ? ["-n", "4", ip] : ["-c", "4", ip]

    const ping = spawn(cmd, args)
    let output = ""

    ping.stdout.on("data", (data) => {
      output += data.toString()
    })

    ping.on("close", () => {
      let loss = 100
      let latency = -1
      let minLatency = -1
      let maxLatency = -1

      // Parse packet loss
      const lossMatch = output.match(/(\d+)%.*loss/i)
      if (lossMatch) {
        loss = Number.parseInt(lossMatch[1])
      }

      // Parse latency statistics
      const latencyMatch =
        output.match(/avg[^=]*=\s*([0-9.]+)/i) || output.match(/Average[^=]*=\s*([0-9.]+)/i)
      if (latencyMatch) {
        latency = Math.round(Number.parseFloat(latencyMatch[1]))
      }

      // Parse min/max latency
      const minMaxMatch = output.match(/min\/avg\/max[^=]*=\s*([0-9.]+)\/[0-9.]+\/([0-9.]+)/i)
      if (minMaxMatch) {
        minLatency = Math.round(Number.parseFloat(minMaxMatch[1]))
        maxLatency = Math.round(Number.parseFloat(minMaxMatch[2]))
      }

      resolve({ loss, latency, minLatency, maxLatency })
    })

    ping.on("error", () => {
      resolve({ loss: 100, latency: -1, minLatency: -1, maxLatency: -1 })
    })
  })
}

// Enhanced port check with service detection
async function checkPort(ip, port) {
  return new Promise((resolve) => {
    const start = Date.now()
    const socket = new net.Socket()

    socket.setTimeout(5000)

    socket.on("connect", () => {
      const duration = Date.now() - start
      socket.destroy()

      // Try to detect service
      const commonPorts = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        993: "IMAPS",
        995: "POP3S",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
      }

      resolve({
        reachable: true,
        duration,
        service: commonPorts[port] || "Unknown",
      })
    })

    socket.on("timeout", () => {
      socket.destroy()
      resolve({ reachable: false, duration: null, service: null })
    })

    socket.on("error", () => {
      resolve({ reachable: false, duration: null, service: null })
    })

    socket.connect(port, ip)
  })
}

// Enhanced traceroute
async function runTraceroute(ip) {
  return new Promise((resolve) => {
    const isWindows = process.platform === "win32"
    const cmd = isWindows ? "tracert" : "traceroute"
    const args = isWindows ? ["-h", "15", ip] : ["-m", "15", ip]

    const traceroute = spawn(cmd, args)
    let output = ""

    const timeout = setTimeout(() => {
      traceroute.kill()
      resolve("Traceroute timeout after 30 seconds")
    }, 30000)

    traceroute.stdout.on("data", (data) => {
      output += data.toString()
    })

    traceroute.on("close", () => {
      clearTimeout(timeout)
      resolve(output || "Traceroute not available")
    })

    traceroute.on("error", () => {
      clearTimeout(timeout)
      resolve("Traceroute not available")
    })
  })
}

// Enhanced analysis endpoint with real-time streaming
app.post("/api/analyze", authenticateToken, checkRateLimit, async (req, res) => {
  const { ips, port } = req.body

  if (!ips || !Array.isArray(ips) || !port) {
    return res.status(400).json({ success: false, message: "Invalid parameters" })
  }

  if (ips.length > 20) {
    return res.status(400).json({ success: false, message: "Maximum 20 IPs allowed per request" })
  }

  res.writeHead(200, {
    "Content-Type": "text/plain; charset=utf-8",
    "Transfer-Encoding": "chunked",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  })

  const allResults = []
  const startTime = Date.now()

  res.write(`🚀 Starting enhanced network analysis for ${ips.length} target(s) on port ${port}\n`)
  res.write(`📊 Analysis started at: ${new Date().toLocaleString()}\n\n`)

  for (let i = 0; i < ips.length; i++) {
    const ip = ips[i]
    res.write(`\n${"=".repeat(60)}\n`)
    res.write(`🎯 Target ${i + 1}/${ips.length}: ${ip}\n`)
    res.write(`${"=".repeat(60)}\n`)

    const result = { IP: ip, Port: port, Timestamp: new Date().toISOString() }

    try {
      // GeoIP Analysis
      res.write("🌍 Performing geolocation lookup...\n")
      const geoInfo = await getIpInfo(ip)
      if (geoInfo) {
        res.write(`📍 Location: ${geoInfo.Country}, ${geoInfo.Region}, ${geoInfo.City}\n`)
        res.write(`🏢 ISP: ${geoInfo.ISP}\n`)
        res.write(`🔢 ASN: ${geoInfo.ASN}\n`)
        res.write(`🌐 Coordinates: ${geoInfo.Latitude}, ${geoInfo.Longitude}\n`)
        res.write(`⏰ Timezone: ${geoInfo.Timezone}\n`)
        result.GeoIP = geoInfo
      } else {
        res.write("⚠️  Geolocation data not available\n")
        result.GeoIP = {}
      }

      // Reverse DNS
      res.write("\n🔍 Performing reverse DNS lookup...\n")
      const ptr = await reverseDnsLookup(ip)
      res.write(`🔗 Hostname: ${ptr}\n`)
      result.ReverseDNS = ptr

      // Ping Analysis
      res.write("\n🏓 Performing ping analysis...\n")
      const pingResult = await pingHost(ip)
      res.write(`📊 Packet Loss: ${pingResult.loss}%\n`)
      res.write(`⚡ Average Latency: ${pingResult.latency} ms\n`)
      if (pingResult.minLatency !== -1) {
        res.write(`📈 Min/Max Latency: ${pingResult.minLatency}/${pingResult.maxLatency} ms\n`)
      }
      result.Ping = {
        PacketLoss: `${pingResult.loss}%`,
        AvgLatency: `${pingResult.latency} ms`,
        MinLatency: `${pingResult.minLatency} ms`,
        MaxLatency: `${pingResult.maxLatency} ms`,
      }

      // Port Analysis
      res.write(`\n🔌 Checking port ${port} connectivity...\n`)
      const portResult = await checkPort(ip, port)
      if (portResult.reachable) {
        res.write(`✅ Port ${port} is OPEN (${portResult.duration} ms)\n`)
        if (portResult.service) {
          res.write(`🔧 Detected service: ${portResult.service}\n`)
        }
      } else {
        res.write(`❌ Port ${port} is CLOSED or filtered\n`)
      }
      result.PortCheck = {
        Reachable: portResult.reachable,
        ResponseTime: portResult.duration ? `${portResult.duration} ms` : "Timeout",
        Service: portResult.service || "Unknown",
      }

      // Traceroute (optional, can be slow)
      if (req.user.role === "admin") {
        res.write("\n🛰️  Performing traceroute (admin only)...\n")
        const traceResult = await runTraceroute(ip)
        res.write(`${traceResult}\n`)
        result.Traceroute = traceResult
      } else {
        result.Traceroute = "Traceroute requires admin privileges"
      }

      allResults.push(result)
    } catch (error) {
      res.write(`❌ Error analyzing ${ip}: ${error.message}\n`)
      result.Error = error.message
      allResults.push(result)
    }

    res.write(`\n✅ Analysis completed for ${ip}\n`)
  }

  try {
    const filename = `analysis_${Date.now()}.json`
    await fs.writeFile(filename, JSON.stringify(allResults, null, 2))
    res.write(`\n💾 Results saved to ${filename}\n`)
  } catch (error) {
    res.write(`\n⚠️  Could not save results: ${error.message}\n`)
  }

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(2)
  res.write(`\n🎉 Analysis completed in ${totalTime} seconds\n`)
  res.write(`📈 Summary: ${allResults.length} targets analyzed\n`)

  res.end()
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: "2.0.0",
  })
})

// Start server
app.listen(PORT, () => {
  console.log(`\n🚀 Modern Network Analyzer Pro`)
  console.log(`🌐 Server running on http://localhost:${PORT}`)
  console.log(`🔐 Default login: admin / password123`)
  console.log(`⚡ Enhanced features enabled`)
  console.log(`${"=".repeat(50)}`)
})
