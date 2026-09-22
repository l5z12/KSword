-- KSword Cheat Engine automatic initialization script.
-- The UI theme script registers deferred initialization first; this script only loads the bridge and opens the PID supplied by the host.

local statusPath = os.getenv("KSWORD_CE_BRIDGE_STATUS_FILE")
local themeStatusPath = nil
if statusPath ~= nil and statusPath ~= "" then
    themeStatusPath = statusPath .. ".theme"
end

local function writeStatus(value)
    if statusPath == nil or statusPath == "" then
        return
    end
    local statusFile = io.open(statusPath, "w")
    if statusFile ~= nil then
        statusFile:write(value)
        statusFile:close()
    end
end

local function readStatus(path)
    if path == nil or path == "" then
        return ""
    end
    local statusFile = io.open(path, "r")
    if statusFile == nil then
        return ""
    end
    local value = statusFile:read("*l") or ""
    statusFile:close()
    return value
end

local function finishBridgeInitialization()
    if type(_G.KSwordApplyR0Caption) == "function" then
        pcall(_G.KSwordApplyR0Caption)
    end
    if readStatus(themeStatusPath) == "ready" then
        writeStatus("ready")
    else
        writeStatus("bridge-ready")
    end
end

local bridgePath = os.getenv("KSWORD_CE_BRIDGE_DLL")
if bridgePath == nil or bridgePath == "" then
    local architecture = cheatEngineIs64Bit() and "x64" or "Win32"
    bridgePath = getCheatEngineDir() .. "..\\..\\bridge\\" ..
        architecture .. "\\KswordCheatEnginePlugin.dll"
end

-- loadPlugin also calls CEPlugin_InitializePlugin; nil indicates that loading or initialization failed.
local loadOk, pluginId = pcall(loadPlugin, bridgePath)
if not loadOk or pluginId == nil then
    writeStatus("failed")
    return
end

-- Wait for the CE main message loop to become idle before opening the target, to avoid synchronously triggering
-- module/memory-region enumeration on the autorun loading stack. The bridge is installed before creating the timer, so the first process handle still goes through KSword.
local targetPid = tonumber(os.getenv("KSWORD_CE_TARGET_PID") or "")
if targetPid ~= nil and targetPid > 0 then
    local openTimer = createTimer(nil, false)
    openTimer.Interval = 750
    openTimer.OnTimer = function(timer)
        timer.Enabled = false
        timer.destroy()
        _G.KSwordBridgeOpenTimer = nil
        local openOk = pcall(openProcess, targetPid)
        if not openOk or getOpenedProcessID() ~= targetPid then
            writeStatus("failed")
            return
        end
        finishBridgeInitialization()
    end
    _G.KSwordBridgeOpenTimer = openTimer
    openTimer.Enabled = true
else
    finishBridgeInitialization()
end
