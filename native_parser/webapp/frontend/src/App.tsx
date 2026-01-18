import { useState, useEffect, useRef, useCallback } from 'react'
import { BrowserRouter, Routes, Route, Link, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import {
  Line, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, AreaChart, Area, Cell, ComposedChart
} from 'recharts'
import './index.css'

const API_BASE = 'http://localhost:8000'
const queryClient = new QueryClient()

// ============== Theme Constants ==============
const COLORS = {
  cyan: '#06b6d4',
  green: '#10b981',
  purple: '#a855f7',
  pink: '#ec4899',
  orange: '#f97316',
  red: '#ef4444',
  blue: '#3b82f6',
  indigo: '#6366f1',
}

// ============== Utility Functions ==============
function formatDuration(minutes: number): string {
  const hours = Math.floor(minutes / 60)
  const mins = Math.round(minutes % 60)
  if (hours > 0) {
    return `${hours}h ${mins}m`
  }
  return `${mins}m`
}

function formatNumber(num: number): string {
  return num.toLocaleString()
}

// ============== API Hooks ==============
function useSummary() {
  return useQuery({
    queryKey: ['summary'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/summary`)
      return res.json()
    }
  })
}

// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _useSleepDashboard() {
  return useQuery({
    queryKey: ['dashboard', 'sleep'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/dashboard/sleep`)
      return res.json()
    }
  })
}

function useActivityDashboard() {
  return useQuery({
    queryKey: ['dashboard', 'activity'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/dashboard/activity`)
      return res.json()
    }
  })
}

function useHRVDashboard() {
  return useQuery({
    queryKey: ['dashboard', 'hrv'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/dashboard/hrv`)
      return res.json()
    }
  })
}

function useSleepStagesDashboard(night: number = -1) {
  return useQuery({
    queryKey: ['dashboard', 'sleep-stages', night],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/dashboard/sleep-stages?night=${night}`)
      return res.json()
    }
  })
}

function useAvailableNights() {
  return useQuery({
    queryKey: ['available-nights'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/dashboard/available-nights`)
      return res.json()
    }
  })
}

function useRawData(endpoint: string, limit = 100) {
  return useQuery({
    queryKey: ['raw', endpoint, limit],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/raw/${endpoint}?limit=${limit}`)
      return res.json()
    }
  })
}

function useSyncInfo() {
  return useQuery({
    queryKey: ['sync-info'],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/sync-info`)
      return res.json()
    },
    refetchInterval: 30000, // Refresh every 30s
  })
}

// ============== Base UI Components ==============

function Navigation() {
  const location = useLocation()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const links = [
    { path: '/', label: 'OVERVIEW', icon: '◉' },
    { path: '/sleep-stages', label: 'SLEEP', icon: '◈' },
    { path: '/hrv', label: 'HRV', icon: '♡' },
    { path: '/activity', label: 'ACTIVITY', icon: '▲' },
    { path: '/raw', label: 'RAW', icon: '▤' },
    { path: '/ring-control', label: 'CONTROL', icon: '⚙' },
  ]

  const isActive = (path: string) => location.pathname === path

  return (
    <nav className="sticky top-0 z-50 border-b border-cyan-500/20" style={{ backgroundColor: 'rgba(3, 7, 18, 0.95)', backdropFilter: 'blur(12px)' }}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="w-3 h-3 rounded-full" style={{ backgroundColor: COLORS.cyan, boxShadow: `0 0 12px ${COLORS.cyan}` }} />
              <div className="absolute inset-0 w-3 h-3 rounded-full animate-ping opacity-30" style={{ backgroundColor: COLORS.cyan }} />
            </div>
            <span className="text-xl font-bold tracking-wider font-mono">
              <span style={{ color: COLORS.cyan }}>OURA</span>
              <span className="text-cyan-700">::</span>
              <span className="text-white">RING</span>
            </span>
          </Link>

          {/* Desktop Nav */}
          <div className="hidden md:flex items-center gap-1">
            {links.map(link => (
              <Link
                key={link.path}
                to={link.path}
                className="px-4 py-2 rounded-lg text-xs font-mono font-medium tracking-wider transition-all duration-200"
                style={{
                  backgroundColor: isActive(link.path) ? `${COLORS.cyan}20` : 'transparent',
                  color: isActive(link.path) ? COLORS.cyan : '#6b7280',
                  border: isActive(link.path) ? `1px solid ${COLORS.cyan}40` : '1px solid transparent',
                  boxShadow: isActive(link.path) ? `0 0 20px ${COLORS.cyan}15` : 'none'
                }}
              >
                <span className="mr-2 opacity-60">{link.icon}</span>
                {link.label}
              </Link>
            ))}
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-lg text-gray-400 hover:text-cyan-400 transition-colors"
            style={{ border: '1px solid rgba(6, 182, 212, 0.2)' }}
          >
            <span className="font-mono text-xl">{mobileMenuOpen ? '✕' : '☰'}</span>
          </button>
        </div>

        {/* Mobile Nav */}
        {mobileMenuOpen && (
          <div className="md:hidden pb-4 pt-2 border-t border-cyan-500/10">
            <div className="flex flex-col gap-1">
              {links.map(link => (
                <Link
                  key={link.path}
                  to={link.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className="px-4 py-3 rounded-lg font-mono text-sm tracking-wider transition-all"
                  style={{
                    backgroundColor: isActive(link.path) ? `${COLORS.cyan}15` : 'transparent',
                    color: isActive(link.path) ? COLORS.cyan : '#9ca3af',
                    borderLeft: isActive(link.path) ? `3px solid ${COLORS.cyan}` : '3px solid transparent'
                  }}
                >
                  <span className="mr-3 opacity-60">{link.icon}</span>
                  {link.label}
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </nav>
  )
}

// Panel container for sections
function Panel({ children, color = COLORS.cyan, title, subtitle, className = '' }: {
  children: React.ReactNode
  color?: string
  title?: string
  subtitle?: string
  className?: string
}) {
  return (
    <div
      className={`relative rounded-xl p-6 overflow-hidden ${className}`}
      style={{
        backgroundColor: 'rgba(0, 0, 0, 0.6)',
        border: `1px solid ${color}25`,
        boxShadow: `0 4px 30px ${color}10, inset 0 1px 0 ${color}10`
      }}
    >
      {/* Top accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-px"
        style={{ background: `linear-gradient(90deg, transparent, ${color}60, transparent)` }}
      />
      {title && (
        <div className="flex items-center gap-3 mb-5">
          <div
            className="w-2 h-2 rounded-full animate-pulse"
            style={{ backgroundColor: color, boxShadow: `0 0 10px ${color}` }}
          />
          <h2 className="text-sm font-mono font-bold uppercase tracking-widest" style={{ color }}>
            {title}
          </h2>
          {subtitle && <span className="text-xs font-mono text-gray-600">// {subtitle}</span>}
        </div>
      )}
      {children}
    </div>
  )
}

// Page header
function PageHeader({ title, accentColor = COLORS.cyan }: { title: string; accentColor?: string }) {
  const [prefix, suffix] = title.includes('::') ? title.split('::') : [title, '']
  return (
    <div className="flex items-center gap-4 mb-8">
      <div
        className="w-1.5 h-10 rounded-full"
        style={{ backgroundColor: accentColor, boxShadow: `0 0 20px ${accentColor}` }}
      />
      <h1 className="text-3xl font-mono font-bold tracking-wider text-white">
        {prefix}
        {suffix && <span style={{ color: accentColor }}>::{suffix}</span>}
      </h1>
    </div>
  )
}

// Stat card
function StatCard({ title, value, unit, trend, color = COLORS.cyan }: {
  title: string
  value: string | number
  unit?: string
  trend?: string
  color?: string
}) {
  return (
    <div
      className="relative rounded-xl p-5 overflow-hidden group transition-transform hover:scale-[1.02]"
      style={{
        backgroundColor: 'rgba(0, 0, 0, 0.6)',
        border: `1px solid ${color}30`,
        boxShadow: `0 4px 20px ${color}10`
      }}
    >
      {/* Corner brackets */}
      <div className="absolute top-2 left-2 w-3 h-3 border-t border-l" style={{ borderColor: `${color}40` }} />
      <div className="absolute top-2 right-2 w-3 h-3 border-t border-r" style={{ borderColor: `${color}40` }} />
      <div className="absolute bottom-2 left-2 w-3 h-3 border-b border-l" style={{ borderColor: `${color}40` }} />
      <div className="absolute bottom-2 right-2 w-3 h-3 border-b border-r" style={{ borderColor: `${color}40` }} />

      <p className="text-gray-500 text-xs font-mono uppercase tracking-widest mb-2">{title}</p>
      <p className="text-3xl font-mono font-bold" style={{ color }}>
        {value}
        {unit && <span className="text-lg text-gray-500 ml-1 font-normal">{unit}</span>}
      </p>
      {trend && <p className="text-xs font-mono text-gray-600 mt-2">› {trend}</p>}
    </div>
  )
}

// Loading state
function LoadingState({ message = 'LOADING...' }: { message?: string }) {
  return (
    <div className="flex items-center justify-center p-16">
      <div className="flex items-center gap-3">
        <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: COLORS.cyan, boxShadow: `0 0 10px ${COLORS.cyan}` }} />
        <span className="text-cyan-400 font-mono text-sm tracking-wider animate-pulse">[ {message} ]</span>
      </div>
    </div>
  )
}

// Error state
function ErrorState({ message = 'FAILED TO LOAD DATA' }: { message?: string }) {
  return (
    <div className="flex items-center justify-center p-16">
      <div className="flex items-center gap-3">
        <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS.red, boxShadow: `0 0 10px ${COLORS.red}` }} />
        <span className="font-mono text-sm tracking-wider" style={{ color: COLORS.red }}>[ ERROR: {message} ]</span>
      </div>
    </div>
  )
}

// Progress bar
function ProgressBar({ value, max, color }: { value: number; max: number; color: string }) {
  const percent = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ backgroundColor: `${color}15` }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${percent}%`, backgroundColor: color, boxShadow: `0 0 10px ${color}` }}
        />
      </div>
      <span className="text-xs font-mono text-gray-500 w-10 text-right">{percent}%</span>
    </div>
  )
}

// Stage card for sleep stages
function StageCard({ name, minutes, totalTime, color }: { name: string; minutes: number; totalTime: number; color: string }) {
  return (
    <div
      className="relative rounded-xl p-5 overflow-hidden"
      style={{
        backgroundColor: 'rgba(0, 0, 0, 0.6)',
        border: `1px solid ${color}30`,
        boxShadow: `0 4px 20px ${color}10`
      }}
    >
      {/* Top glow line */}
      <div
        className="absolute top-0 left-0 right-0 h-1"
        style={{ background: `linear-gradient(90deg, transparent, ${color}, transparent)` }}
      />
      <p className="text-gray-500 text-xs font-mono uppercase tracking-widest">{name}</p>
      <p className="text-2xl font-mono font-bold mt-2" style={{ color }}>{formatDuration(minutes)}</p>
      <div className="mt-4">
        <ProgressBar value={minutes} max={totalTime} color={color} />
      </div>
    </div>
  )
}

// Score contributor mini card
function ScoreContributor({ label, value }: { label: string; value?: number }) {
  const score = value || 0
  const color = score >= 80 ? COLORS.green : score >= 60 ? COLORS.orange : COLORS.red
  return (
    <div className="flex items-center justify-between px-3 py-2 rounded-lg bg-black/40 border border-gray-800">
      <span className="text-xs text-gray-500 uppercase">{label}</span>
      <span className="text-sm font-mono font-bold" style={{ color }}>{score}</span>
    </div>
  )
}

// Chart tooltip style
const tooltipStyle = (color: string) => ({
  contentStyle: {
    backgroundColor: 'rgba(0, 0, 0, 0.9)',
    border: `1px solid ${color}50`,
    borderRadius: '8px',
    fontFamily: 'monospace',
    fontSize: '12px',
    boxShadow: `0 4px 20px ${color}20`
  },
  itemStyle: { color: '#e5e7eb' },
  labelStyle: { color: '#9ca3af' }
})

// ============== Page Components ==============

function Overview() {
  const { data: summary, isLoading, error } = useSummary()

  if (isLoading) return <LoadingState message="LOADING SYSTEM DATA..." />
  if (error) return <ErrorState message="BACKEND OFFLINE - START SERVER" />

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">
      <PageHeader title="SYSTEM::OVERVIEW" accentColor={COLORS.cyan} />

      {/* Ring Info Panel */}
      <Panel color={COLORS.cyan} title="Ring Hardware" subtitle="Device information" className="mb-8">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Ring Type</p>
            <p className="text-lg font-mono text-white mt-1">{summary?.ring_info?.ring_type || 'GEN3'}</p>
          </div>
          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Firmware</p>
            <p className="text-lg font-mono text-cyan-400 mt-1">{summary?.ring_info?.firmware_version || '—'}</p>
          </div>
          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Bootloader</p>
            <p className="text-lg font-mono text-cyan-400 mt-1">{summary?.ring_info?.bootloader_version || '—'}</p>
          </div>
          <div>
            <p className="text-xs font-mono text-gray-500 uppercase tracking-wider">Serial</p>
            <p className="text-lg font-mono text-gray-400 mt-1">{summary?.ring_info?.serial_number || 'N/A'}</p>
          </div>
        </div>
      </Panel>

      {/* Data Samples Grid */}
      <h2 className="text-sm font-mono font-bold text-gray-500 uppercase tracking-widest mb-4">
        <span className="text-cyan-500">›</span> Available Data Samples
      </h2>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard title="Heart Rate" value={formatNumber(summary?.heart_rate_samples || 0)} color={COLORS.pink} />
        <StatCard title="Sleep" value={formatNumber(summary?.sleep_samples || 0)} color={COLORS.purple} />
        <StatCard title="Temperature" value={formatNumber(summary?.temperature_samples || 0)} color={COLORS.orange} />
        <StatCard title="HRV" value={formatNumber(summary?.hrv_samples || 0)} color={COLORS.green} />
        <StatCard title="SpO2" value={formatNumber(summary?.spo2_samples || 0)} color={COLORS.blue} />
        <StatCard title="Activity" value={formatNumber(summary?.activity_samples || 0)} color={COLORS.orange} />
        <StatCard title="Motion" value={formatNumber(summary?.motion_samples || 0)} color={COLORS.cyan} />
      </div>
    </div>
  )
}

function SleepStagesDashboard() {
  const [selectedNight, setSelectedNight] = useState(-1)
  const { data: nightsData } = useAvailableNights()
  const { data, isLoading, error } = useSleepStagesDashboard(selectedNight)
  const { data: syncInfo } = useSyncInfo()

  if (isLoading) return <LoadingState message="ANALYZING SLEEP DATA..." />
  if (error) return <ErrorState message="FAILED TO LOAD SLEEP DATA" />

  const nights = nightsData?.nights || []
  const lastUpdated = syncInfo?.last_updated ? new Date(syncInfo.last_updated).toLocaleString() : null

  // Hypnogram: Deep at top (3), Awake at bottom (0)
  // Backend stage: 0=Deep, 1=Light, 2=REM, 3=Awake
  // Invert: Deep(0)->3, Light(1)->2, REM(2)->1, Awake(3)->0
  // Merge HR samples by time for overlay
  const hrByTime = new Map((data?.hr_samples || []).map((s: any) => [s.time, s.hr]))
  const hypnogramData = data?.epochs?.map((epoch: any, idx: number) => ({
    ...epoch,
    idx,  // Unique index for X-axis to avoid duplicate time issues
    stageY: 3 - epoch.stage,
    hr: hrByTime.get(epoch.time) || null,
  })) || []

  const durations = data?.durations || {}
  const totalTime = durations.total_time_minutes || 1
  const sleepScore = data?.score || {}
  const bedtimeStart = data?.bedtime_start || ''
  const bedtimeEnd = data?.bedtime_end || ''

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <PageHeader title="SLEEP::STAGES" accentColor={COLORS.purple} />
          {lastUpdated && (
            <div className="text-xs font-mono text-gray-500 -mt-6 ml-6">
              Ring data last updated: <span className="text-purple-400">{lastUpdated}</span>
            </div>
          )}
        </div>

        {/* Night Selector */}
        {nights.length > 0 && (
          <div className="flex items-center gap-3">
            <label className="text-xs font-mono text-gray-500 uppercase tracking-wider">Night:</label>
            <select
              value={selectedNight}
              onChange={(e) => setSelectedNight(parseInt(e.target.value))}
              className="font-mono text-sm px-4 py-2 rounded-lg bg-black/60 text-purple-400 focus:outline-none"
              style={{ border: `1px solid ${COLORS.purple}40` }}
            >
              {nights.map((night: any, idx: number) => (
                <option key={idx} value={idx}>
                  {night.date} ({night.duration})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Sleep Score Hero */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        {/* Main Score Circle */}
        <div className="flex items-center justify-center">
          <div className="relative">
            <svg className="w-40 h-40" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="45" fill="none" stroke={`${COLORS.purple}20`} strokeWidth="8" />
              <circle
                cx="50" cy="50" r="45" fill="none" stroke={COLORS.purple} strokeWidth="8"
                strokeLinecap="round" strokeDasharray={`${(sleepScore.score || 0) * 2.83} 283`}
                transform="rotate(-90 50 50)"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-4xl font-bold text-white font-mono">{sleepScore.score || 0}</span>
              <span className="text-xs text-gray-500 uppercase tracking-wider">Sleep Score</span>
            </div>
          </div>
        </div>

        {/* Bedtime Window */}
        <div className="flex flex-col justify-center space-y-3">
          <div className="text-center md:text-left">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Bedtime</span>
            <div className="text-2xl font-mono text-white">{bedtimeStart || '--:--'}</div>
          </div>
          <div className="text-center md:text-left">
            <span className="text-xs text-gray-500 uppercase tracking-wider">Wake Time</span>
            <div className="text-2xl font-mono text-white">{bedtimeEnd || '--:--'}</div>
          </div>
        </div>

        {/* Score Contributors */}
        <div className="grid grid-cols-2 gap-2">
          <ScoreContributor label="Duration" value={sleepScore.total_sleep} />
          <ScoreContributor label="Efficiency" value={sleepScore.efficiency} />
          <ScoreContributor label="Deep" value={sleepScore.deep_sleep} />
          <ScoreContributor label="REM" value={sleepScore.rem_sleep} />
          <ScoreContributor label="Latency" value={sleepScore.latency} />
          <ScoreContributor label="Timing" value={sleepScore.timing} />
        </div>
      </div>

      {/* Hypnogram */}
      <Panel color={COLORS.purple} title="Hypnogram" subtitle="Sleep stages + Heart Rate" className="mb-8">
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={hypnogramData}>
              <defs>
                <linearGradient id="sleepGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={COLORS.purple} stopOpacity={0.5} />
                  <stop offset="100%" stopColor={COLORS.purple} stopOpacity={0.05} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={`${COLORS.purple}15`} />
              <XAxis
                dataKey="idx"
                stroke="#4b5563"
                domain={[0, hypnogramData.length + 60]}
                interval={Math.floor(hypnogramData.length / 8)}
                tickFormatter={(idx) => hypnogramData[idx]?.time || ''}
                tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }}
              />
              <YAxis
                yAxisId="stage"
                stroke="#4b5563"
                domain={[0, 3]}
                ticks={[0, 1, 2, 3]}
                tickFormatter={(v) => ['AWAKE', 'REM', 'LIGHT', 'DEEP'][v] || ''}
                tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }}
                width={55}
              />
              <YAxis
                yAxisId="hr"
                orientation="right"
                stroke={COLORS.red}
                domain={[40, 100]}
                tick={{ fontSize: 10, fontFamily: 'monospace', fill: COLORS.red }}
                tickFormatter={(v) => `${v}`}
                width={35}
              />
              <Tooltip
                {...tooltipStyle(COLORS.purple)}
                formatter={(value: any, name: any, props: any) => {
                  if (name === 'hr') return value ? [`${value} bpm`, 'Heart Rate'] : ['--', 'Heart Rate']
                  const stageNames = ['AWAKE', 'REM', 'LIGHT', 'DEEP']
                  return [stageNames[value] || value, 'Stage']
                }}
                labelFormatter={(idx: any) => {
                  const epoch = hypnogramData[idx]
                  return epoch ? `Time: ${epoch.time}` : `Index: ${idx}`
                }}
              />
              <Area yAxisId="stage" type="stepAfter" dataKey="stageY" stroke={COLORS.purple} fill="url(#sleepGradient)" strokeWidth={2} />
              <Line yAxisId="hr" type="monotone" dataKey="hr" stroke={COLORS.red} strokeWidth={1.5} dot={false} connectNulls />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      {/* Stage Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StageCard name="DEEP" minutes={durations.deep_minutes || 0} totalTime={totalTime} color={COLORS.indigo} />
        <StageCard name="REM" minutes={durations.rem_minutes || 0} totalTime={totalTime} color={COLORS.purple} />
        <StageCard name="LIGHT" minutes={durations.light_minutes || 0} totalTime={totalTime} color={COLORS.blue} />
        <StageCard name="AWAKE" minutes={durations.awake_minutes || 0} totalTime={totalTime} color={COLORS.red} />
      </div>

      {/* Biometrics */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        <StatCard title="Avg Heart Rate" value={data?.average_heart_rate || 0} unit="bpm" color={COLORS.red} />
        <StatCard title="Avg Breath Rate" value={data?.average_breath_rate || 0} unit="br/m" color={COLORS.cyan} />
        <StatCard title="Avg HRV" value={data?.average_hrv || 0} unit="ms" color={COLORS.green} />
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        <StatCard title="Total Sleep" value={formatDuration(durations.total_sleep_minutes || 0)} color={COLORS.purple} />
        <StatCard title="Time in Bed" value={formatDuration(durations.total_time_minutes || 0)} color={COLORS.cyan} />
        <StatCard title="Efficiency" value={Math.round(durations.efficiency_percent || 0)} unit="%" color={COLORS.green} />
      </div>
    </div>
  )
}

function HRVDashboardPage() {
  const { data, isLoading, error } = useHRVDashboard()

  if (isLoading) return <LoadingState message="ANALYZING HRV DATA..." />
  if (error) return <ErrorState message="FAILED TO LOAD HRV DATA" />

  const byStageData = Object.entries(data?.by_sleep_stage || {})
    .map(([stage, value]) => ({
      stage: stage.toUpperCase(),
      rmssd: value as number,
      fill: stage === 'deep' ? COLORS.indigo : stage === 'rem' ? COLORS.purple : stage === 'light' ? COLORS.blue : COLORS.red
    }))
    .filter(s => s.rmssd > 0)
    .sort((a, b) => b.rmssd - a.rmssd)

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">
      <PageHeader title="HRV::ANALYSIS" accentColor={COLORS.green} />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard title="Average RMSSD" value={data?.average_rmssd || 0} unit="ms" color={COLORS.green} />
        <StatCard title="Min RMSSD" value={data?.min_rmssd || 0} unit="ms" color={COLORS.cyan} />
        <StatCard title="Max RMSSD" value={data?.max_rmssd || 0} unit="ms" color={COLORS.purple} />
        <StatCard title="Samples" value={data?.sample_count || 0} trend="5-min intervals" color={COLORS.orange} />
      </div>

      {/* HRV Timeline */}
      <Panel color={COLORS.green} title="HRV Timeline" subtitle="5-minute RMSSD intervals" className="mb-8">
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data?.samples_5min || []}>
              <defs>
                <linearGradient id="hrvGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={COLORS.green} stopOpacity={0.5} />
                  <stop offset="100%" stopColor={COLORS.green} stopOpacity={0.05} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={`${COLORS.green}15`} />
              <XAxis
                dataKey="time"
                stroke="#4b5563"
                interval={Math.floor((data?.samples_5min?.length || 1) / 8)}
                tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }}
              />
              <YAxis stroke="#4b5563" tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
              <Tooltip {...tooltipStyle(COLORS.green)} formatter={(value) => [`${value} ms`, 'RMSSD']} />
              <Area type="monotone" dataKey="rmssd" stroke={COLORS.green} fill="url(#hrvGradient)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Panel>

      {/* HRV by Stage */}
      <Panel color={COLORS.green} title="HRV by Sleep Stage">
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={byStageData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke={`${COLORS.green}15`} />
              <XAxis type="number" stroke="#4b5563" tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
              <YAxis type="category" dataKey="stage" stroke="#4b5563" width={55} tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
              <Tooltip {...tooltipStyle(COLORS.green)} formatter={(value) => [`${Number(value).toFixed(1)} ms`, 'Avg RMSSD']} />
              <Bar dataKey="rmssd" radius={[0, 6, 6, 0]}>
                {byStageData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Panel>
    </div>
  )
}

function ActivityDashboard() {
  const { data, isLoading, error } = useActivityDashboard()

  if (isLoading) return <LoadingState message="LOADING ACTIVITY DATA..." />
  if (error) return <ErrorState message="FAILED TO LOAD ACTIVITY DATA" />

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">
      <PageHeader title="ACTIVITY::TRACKING" accentColor={COLORS.orange} />

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard title="Total Steps" value={formatNumber(data?.total_steps || 0)} color={COLORS.green} />
        <StatCard title="Calories" value={data?.total_calories || 0} unit="kcal" color={COLORS.orange} />
        <StatCard title="MET Minutes" value={data?.total_met_minutes || 0} color={COLORS.cyan} />
        <StatCard title="Active Hours" value={data?.active_hours || 0} color={COLORS.purple} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Steps Chart */}
        <Panel color={COLORS.green} title="Steps per Hour">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.steps_per_hour || []}>
                <CartesianGrid strokeDasharray="3 3" stroke={`${COLORS.green}15`} />
                <XAxis dataKey="hour" stroke="#4b5563" tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
                <YAxis stroke="#4b5563" tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
                <Tooltip {...tooltipStyle(COLORS.green)} />
                <Bar dataKey="steps" fill={COLORS.green} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        {/* Calories Chart */}
        <Panel color={COLORS.orange} title="Calories per Hour">
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data?.calories_per_hour || []}>
                <CartesianGrid strokeDasharray="3 3" stroke={`${COLORS.orange}15`} />
                <XAxis dataKey="hour" stroke="#4b5563" tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
                <YAxis stroke="#4b5563" tick={{ fontSize: 10, fontFamily: 'monospace', fill: '#6b7280' }} />
                <Tooltip {...tooltipStyle(COLORS.orange)} />
                <Bar dataKey="calories" fill={COLORS.orange} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>
    </div>
  )
}

function RawDataBrowser() {
  const [selectedEndpoint, setSelectedEndpoint] = useState('heart-rate')
  const { data, isLoading, error } = useRawData(selectedEndpoint, 200)

  const endpoints = [
    { value: 'heart-rate', label: 'Heart Rate / IBI' },
    { value: 'sleep', label: 'Sleep Data' },
    { value: 'temperature', label: 'Temperature' },
    { value: 'hrv', label: 'HRV' },
    { value: 'activity', label: 'Activity' },
    { value: 'motion', label: 'Motion' },
    { value: 'spo2', label: 'SpO2' },
  ]

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">
      <PageHeader title="RAW::DATA" accentColor={COLORS.cyan} />

      {/* Endpoint Selector */}
      <Panel color={COLORS.cyan} className="mb-6">
        <div className="flex flex-wrap items-center gap-4">
          <label className="text-xs font-mono text-gray-500 uppercase tracking-wider">Select Data Type:</label>
          <select
            value={selectedEndpoint}
            onChange={(e) => setSelectedEndpoint(e.target.value)}
            className="font-mono text-sm px-4 py-2 rounded-lg bg-black/60 text-cyan-400 focus:outline-none"
            style={{ border: `1px solid ${COLORS.cyan}40` }}
          >
            {endpoints.map(ep => (
              <option key={ep.value} value={ep.value}>{ep.label}</option>
            ))}
          </select>
          {data && (
            <span className="text-xs font-mono text-gray-500">
              Showing {data.samples?.length || 0} of {formatNumber(data.sample_count || data.total_samples || 0)} samples
            </span>
          )}
        </div>
      </Panel>

      {/* Data Table */}
      <Panel color={COLORS.cyan} title="Data Samples">
        {isLoading ? (
          <LoadingState message="FETCHING DATA..." />
        ) : error ? (
          <ErrorState message="FAILED TO LOAD DATA" />
        ) : (
          <div className="overflow-x-auto max-h-[500px] overflow-y-auto rounded-lg" style={{ border: `1px solid ${COLORS.cyan}20` }}>
            <table className="w-full text-sm font-mono">
              <thead className="sticky top-0" style={{ backgroundColor: 'rgba(6, 182, 212, 0.1)' }}>
                <tr>
                  {data?.samples?.[0] && Object.keys(data.samples[0]).map(key => (
                    <th key={key} className="px-4 py-3 text-left text-xs font-bold uppercase tracking-wider text-cyan-400">
                      {key}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {data?.samples?.map((sample: any, idx: number) => (
                  <tr key={idx} className="hover:bg-cyan-500/5 transition-colors">
                    {Object.values(sample).map((val: any, vidx) => (
                      <td key={vidx} className="px-4 py-2 text-gray-400">
                        {typeof val === 'number' ? val.toLocaleString() : String(val)}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}

// ============== Ring Control Page ==============

// Types for BLE WebSocket
interface LogEntry {
  level: string
  message: string
  time: Date
}

interface HeartbeatData {
  bpm: number
  ibi: number
  count: number
}

// Real-time heartbeat chart component - hacker style
function HeartbeatChart({ history }: { history: number[] }) {
  const width = 300
  const height = 80
  const maxPoints = 50

  if (history.length < 2) return null

  const data = history.slice(-maxPoints)
  const min = Math.min(...data) - 5
  const max = Math.max(...data) + 5
  const range = max - min || 1

  const points = data.map((bpm, i) => {
    const x = (i / (maxPoints - 1)) * width
    const y = height - ((bpm - min) / range) * height
    return `${x},${y}`
  }).join(' ')

  // Create the "pulse" effect path
  const lastBpm = data[data.length - 1]
  const pulseY = height - ((lastBpm - min) / range) * height

  return (
    <div className="relative">
      <svg width={width} height={height} className="overflow-visible">
        {/* Grid lines */}
        <defs>
          <linearGradient id="lineGradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#0f172a" />
            <stop offset="50%" stopColor="#10b981" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
          <linearGradient id="scanGlow" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="transparent" />
            <stop offset="100%" stopColor="#22d3ee" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>

        {/* Horizontal grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map(p => (
          <line
            key={p}
            x1="0" y1={p * height}
            x2={width} y2={p * height}
            stroke="#1e293b"
            strokeWidth="1"
          />
        ))}

        {/* The heartbeat line - with smooth transition */}
        <polyline
          points={points}
          fill="none"
          stroke="url(#lineGradient)"
          strokeWidth="2"
          filter="url(#glow)"
          strokeLinejoin="round"
          strokeLinecap="round"
          style={{ transition: 'all 0.15s ease-out' }}
        />

        {/* Pulsing dot at the end - smooth position */}
        <circle
          cx={width}
          cy={pulseY}
          r="5"
          fill="#22d3ee"
          filter="url(#glow)"
          style={{ transition: 'cy 0.15s ease-out' }}
        >
          <animate attributeName="r" values="4;6;4" dur="1s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="1;0.6;1" dur="1s" repeatCount="indefinite" />
        </circle>

        {/* Moving scanline effect */}
        <line
          x1="0" y1="0"
          x2="0" y2={height}
          stroke="#22d3ee"
          strokeWidth="2"
          opacity="0.2"
        >
          <animate attributeName="x1" values={`0;${width};0`} dur="3s" repeatCount="indefinite" />
          <animate attributeName="x2" values={`0;${width};0`} dur="3s" repeatCount="indefinite" />
        </line>

        {/* Trailing glow behind scanline */}
        <rect x="0" y="0" width="30" height={height} fill="url(#scanGlow)" opacity="0.3">
          <animate attributeName="x" values={`-30;${width};-30`} dur="3s" repeatCount="indefinite" />
        </rect>
      </svg>

      {/* Min/Max labels */}
      <div className="absolute right-0 top-0 text-[10px] font-mono text-cyan-600">{Math.round(max)}</div>
      <div className="absolute right-0 bottom-0 text-[10px] font-mono text-cyan-600">{Math.round(min)}</div>
    </div>
  )
}

interface BLEStatus {
  connected: boolean
  authenticated: boolean
  is_busy: boolean
  current_action: string | null
}

// WebSocket hook for BLE communication
function useBLEWebSocket() {
  const [status, setStatus] = useState<BLEStatus>({
    connected: false,
    authenticated: false,
    is_busy: false,
    current_action: null
  })
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [heartbeat, setHeartbeat] = useState<HeartbeatData | null>(null)
  const [heartbeatHistory, setHeartbeatHistory] = useState<number[]>([])
  const [progress, setProgress] = useState<{ action: string; current: number; total: number; label: string } | null>(null)
  const [wsConnected, setWsConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket('ws://localhost:8000/ble/ws')
      wsRef.current = ws

      ws.onopen = () => {
        setWsConnected(true)
        setLogs(prev => [...prev, { level: 'info', message: 'WebSocket connected to backend', time: new Date() }])
      }

      ws.onclose = () => {
        setWsConnected(false)
        setLogs(prev => [...prev, { level: 'warn', message: 'WebSocket disconnected', time: new Date() }])
        // Auto-reconnect after 3 seconds
        setTimeout(connect, 3000)
      }

      ws.onerror = () => {
        setLogs(prev => [...prev, { level: 'error', message: 'WebSocket error', time: new Date() }])
      }

      ws.onmessage = (event) => {
        const msg = JSON.parse(event.data)
        switch (msg.type) {
          case 'log':
            setLogs(prev => [...prev, { level: msg.level, message: msg.message, time: new Date() }])
            break
          case 'status':
            setStatus({
              connected: msg.connected,
              authenticated: msg.authenticated,
              is_busy: msg.is_busy,
              current_action: msg.current_action
            })
            break
          case 'heartbeat':
            setHeartbeat({ bpm: msg.bpm, ibi: msg.ibi, count: msg.count })
            setHeartbeatHistory(prev => [...prev.slice(-99), msg.bpm])  // Keep last 100
            break
          case 'progress':
            setProgress({ action: msg.action, current: msg.current, total: msg.total, label: msg.label })
            break
          case 'complete':
            setProgress(null)
            setLogs(prev => [...prev, {
              level: msg.success ? 'success' : 'error',
              message: `${msg.action} ${msg.success ? 'completed' : 'failed'}${msg.event_count !== undefined ? ` (${msg.event_count} events)` : ''}`,
              time: new Date()
            }])
            // Invalidate queries if data was fetched or updated
            if ((msg.action === 'get-data' || msg.action === 'update-ring' || msg.action === 'parse') && msg.success) {
              queryClient.invalidateQueries({ queryKey: ['dashboard'] })
              queryClient.invalidateQueries({ queryKey: ['summary'] })
              queryClient.invalidateQueries({ queryKey: ['raw'] })
              queryClient.invalidateQueries({ queryKey: ['sync-info'] })
            }
            break
          case 'error':
            setLogs(prev => [...prev, { level: 'error', message: msg.message, time: new Date() }])
            break
          case 'sync':
            // Sync point received - no extra log needed, client.py already logged it
            break
        }
      }
    }

    connect()

    return () => {
      if (wsRef.current) {
        wsRef.current.close()
      }
    }
  }, [])

  const send = useCallback((action: string, data?: object) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action, ...data }))
    }
  }, [])

  const clearLogs = useCallback(() => setLogs([]), [])
  const clearHeartbeat = useCallback(() => {
    setHeartbeat(null)
    setHeartbeatHistory([])
  }, [])

  return { status, logs, heartbeat, heartbeatHistory, progress, wsConnected, send, clearLogs, clearHeartbeat }
}

// Status indicator component
function StatusIndicator({ label, active, color }: { label: string; active: boolean; color?: string }) {
  const activeColor = color || COLORS.green
  const inactiveColor = COLORS.red
  return (
    <div className="flex items-center gap-3 mb-2">
      <div
        className="w-3 h-3 rounded-full transition-all duration-300"
        style={{
          backgroundColor: active ? activeColor : inactiveColor,
          boxShadow: active ? `0 0 10px ${activeColor}` : 'none'
        }}
      />
      <span className="text-sm font-mono text-gray-400">{label}</span>
      <span className="text-xs font-mono" style={{ color: active ? activeColor : inactiveColor }}>
        {active ? 'ACTIVE' : 'INACTIVE'}
      </span>
    </div>
  )
}

// Action button component
function ActionButton({ label, onClick, disabled, color = COLORS.cyan, loading = false }: {
  label: string
  onClick: () => void
  disabled?: boolean
  color?: string
  loading?: boolean
}) {
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className="px-4 py-2 rounded-lg font-mono text-sm uppercase tracking-wider transition-all"
      style={{
        backgroundColor: disabled ? '#1f2937' : `${color}20`,
        color: disabled ? '#4b5563' : color,
        border: `1px solid ${disabled ? '#374151' : color}40`,
        cursor: disabled ? 'not-allowed' : 'pointer',
        opacity: disabled ? 0.5 : 1
      }}
    >
      {loading ? '...' : label}
    </button>
  )
}

// Terminal output component
function TerminalOutput({ logs }: { logs: LogEntry[] }) {
  const endRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const getColor = (level: string) => {
    switch (level) {
      case 'success': return COLORS.green
      case 'error': return COLORS.red
      case 'warn': return COLORS.orange
      default: return COLORS.cyan
    }
  }

  const getIcon = (level: string) => {
    switch (level) {
      case 'success': return '✓'
      case 'error': return '✗'
      case 'warn': return '!'
      default: return '›'
    }
  }

  return (
    <div className="bg-black/50 rounded-lg p-4 h-80 overflow-y-auto font-mono text-sm">
      {logs.length === 0 && (
        <div className="text-gray-600 text-center py-8">No logs yet. Connect to start.</div>
      )}
      {logs.map((log, i) => (
        <div key={i} className="flex gap-2 mb-1">
          <span className="text-gray-600 text-xs min-w-[70px]">
            {log.time.toLocaleTimeString()}
          </span>
          <span style={{ color: getColor(log.level) }}>
            {getIcon(log.level)}
          </span>
          <span className="text-gray-300 whitespace-pre-wrap break-words flex-1">
            {log.message}
          </span>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  )
}

// Filter chip component (for future use)
// eslint-disable-next-line @typescript-eslint/no-unused-vars
function _FilterChip({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="px-3 py-1.5 rounded-full font-mono text-xs uppercase tracking-wider transition-all"
      style={{
        backgroundColor: active ? `${COLORS.cyan}30` : 'transparent',
        color: active ? COLORS.cyan : '#6b7280',
        border: `1px solid ${active ? COLORS.cyan : '#374151'}40`
      }}
    >
      {label}
    </button>
  )
}

// Confirmation dialog component
function ConfirmDialog({ action, onConfirm, onCancel }: {
  action: 'pair' | 'unpair' | 'factory-reset'
  onConfirm: () => void
  onCancel: () => void
}) {
  const [confirmText, setConfirmText] = useState('')

  const config = {
    'pair': {
      title: 'Pair with Ring',
      warning: 'Make sure ring is in PAIRING MODE (white light on charger, then remove).',
      confirm: 'Start Pairing',
      color: COLORS.orange,
      requireType: null
    },
    'unpair': {
      title: 'Unpair Ring',
      warning: 'This will remove the Bluetooth pairing from this PC. Ring data stays intact. You will need to pair again to connect.',
      confirm: 'Unpair',
      color: COLORS.orange,
      requireType: null
    },
    'factory-reset': {
      title: 'FACTORY RESET',
      warning: 'This will PERMANENTLY ERASE all data on the ring including auth key. This cannot be undone!',
      confirm: 'Yes, Factory Reset',
      color: COLORS.red,
      requireType: 'FACTORY RESET'
    }
  }

  const cfg = config[action]
  const canConfirm = cfg.requireType ? confirmText === cfg.requireType : true

  return (
    <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4">
      <div
        className="rounded-xl p-6 max-w-md w-full"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.95)',
          border: `1px solid ${cfg.color}50`,
          boxShadow: `0 0 40px ${cfg.color}20`
        }}
      >
        <h3 className="text-xl font-mono font-bold mb-4" style={{ color: cfg.color }}>
          {action === 'factory-reset' && '⚠️ '}{cfg.title}
        </h3>
        <p className="text-gray-400 text-sm mb-4">{cfg.warning}</p>

        {cfg.requireType && (
          <div className="mb-4">
            <p className="text-xs text-gray-500 mb-2">Type "{cfg.requireType}" to confirm:</p>
            <input
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              className="w-full bg-black/60 border border-gray-700 rounded px-3 py-2 font-mono text-white focus:outline-none focus:border-red-500"
              placeholder={cfg.requireType}
            />
          </div>
        )}

        <div className="flex gap-3 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-2 rounded-lg font-mono text-sm text-gray-400 border border-gray-700 hover:border-gray-500 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={!canConfirm}
            className="px-4 py-2 rounded-lg font-mono text-sm transition-all"
            style={{
              backgroundColor: canConfirm ? `${cfg.color}30` : '#1f2937',
              color: canConfirm ? cfg.color : '#4b5563',
              border: `1px solid ${canConfirm ? cfg.color : '#374151'}40`
            }}
          >
            {cfg.confirm}
          </button>
        </div>
      </div>
    </div>
  )
}

// Main Ring Control Page
function RingControlPage() {
  const { status, logs, heartbeat, heartbeatHistory, progress, wsConnected, send, clearLogs, clearHeartbeat } = useBLEWebSocket()
  const { data: syncInfo } = useSyncInfo()
  const [isHeartbeatActive, setIsHeartbeatActive] = useState(false)
  interface AdapterInfo {
    id: string
    name: string
    product: string
  }
  const [adapters, setAdapters] = useState<AdapterInfo[]>([{ id: 'hci0', name: 'hci0', product: '' }])
  const [selectedAdapter, setSelectedAdapter] = useState('hci0')
  const [selectedFilter] = useState('all')
  const [confirmDialog, setConfirmDialog] = useState<'pair' | 'unpair' | 'factory-reset' | null>(null)
  const [authKeyInput, setAuthKeyInput] = useState('00426ed816dcece48dd9968c1f36c0b5')

  // Fetch available adapters on mount
  useEffect(() => {
    fetch(`${API_BASE}/ble/adapters`)
      .then(res => res.json())
      .then(data => {
        const adapterList = data.adapters || [{ id: 'hci0', name: 'hci0', product: '' }]
        setAdapters(adapterList)
        setSelectedAdapter(data.default || adapterList[0]?.id || 'hci0')
      })
      .catch(() => {})
  }, [])

  const handleConnect = () => send('connect', { adapter: selectedAdapter })
  const handleDisconnect = () => {
    send('disconnect')
    setIsHeartbeatActive(false)
    clearHeartbeat()
  }
  const handleAuth = () => send('auth')
  const handleSyncTime = () => send('sync-time')
  const handleUpdateRing = () => {
    send('update-ring')
    // Refetch sync info after update completes (via WebSocket complete event)
  }
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const _handleGetData = () => send('get-data', { filters: { preset: selectedFilter } })

  const handleHeartbeat = () => {
    if (isHeartbeatActive) {
      send('heartbeat', { command: 'stop' })
      setIsHeartbeatActive(false)
      clearHeartbeat()
    } else {
      send('heartbeat', { command: 'start' })
      setIsHeartbeatActive(true)
    }
  }

  const handlePair = () => setConfirmDialog('pair')
  const handleUnpair = () => setConfirmDialog('unpair')
  const handleFactoryReset = () => setConfirmDialog('factory-reset')
  const handleSetAuthKey = () => {
    if (authKeyInput.replace(/\s/g, '').length !== 32) {
      alert('Auth key must be 32 hex characters (16 bytes)')
      return
    }
    send('set-auth-key', { key: authKeyInput })
  }

  const confirmAction = () => {
    if (confirmDialog === 'pair') {
      send('bond', { adapter: selectedAdapter })
    } else if (confirmDialog === 'unpair') {
      send('unpair')
    } else if (confirmDialog === 'factory-reset') {
      send('factory-reset')
    }
    setConfirmDialog(null)
  }

  // Check if BLE is available (not in Docker mode)
  const bleUnavailable = adapters.length === 0 || (adapters.length === 1 && selectedAdapter === 'none')

  return (
    <div className="p-6 md:p-8 max-w-7xl mx-auto">
      <PageHeader title="RING::CONTROL" accentColor={COLORS.cyan} />

      {/* Docker Mode Warning */}
      {bleUnavailable && (
        <div className="mb-6 p-4 rounded-xl border" style={{
          backgroundColor: 'rgba(249, 115, 22, 0.1)',
          borderColor: 'rgba(249, 115, 22, 0.3)'
        }}>
          <h3 className="text-orange-400 font-mono font-bold mb-2">DOCKER MODE - BLE UNAVAILABLE</h3>
          <p className="text-gray-400 text-sm mb-3">
            Bluetooth is not available in Docker. To sync data from your ring, run on the host:
          </p>
          <code className="block bg-black/50 p-3 rounded font-mono text-xs text-cyan-400 mb-3">
            uv run oura-ble --get-data-incremental
          </code>
          <p className="text-gray-500 text-xs">
            Data syncs to input_data/ which Docker reads automatically. Refresh this page after syncing.
          </p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Status Panel */}
        <Panel color={COLORS.cyan} title="Connection Status">
          <StatusIndicator label="WebSocket" active={wsConnected} color={COLORS.cyan} />
          <StatusIndicator label="BLE Connected" active={status.connected} />
          <StatusIndicator label="Authenticated" active={status.authenticated} />
          {status.is_busy && status.current_action && (
            <div className="mt-4 flex items-center gap-2">
              <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: COLORS.orange }} />
              <span className="text-xs font-mono text-orange-400 uppercase">
                {status.current_action}...
              </span>
            </div>
          )}
          {/* Ring Data Info */}
          <div className="mt-4 pt-4 border-t border-cyan-500/20">
            <div className="text-xs font-mono text-gray-500 uppercase tracking-wider mb-2">Ring Data</div>
            {syncInfo?.last_updated ? (
              <>
                <div className="text-xs font-mono text-gray-400">
                  Last updated: <span className="text-cyan-400">{new Date(syncInfo.last_updated).toLocaleString()}</span>
                </div>
                <div className="text-xs font-mono text-gray-400 mt-1">
                  Events: <span className="text-cyan-400">{syncInfo.events_count?.toLocaleString() || 0}</span>
                </div>
                {syncInfo.needs_parse && (
                  <div className="text-xs font-mono text-orange-400 mt-1">
                    ⚠ Needs parsing
                  </div>
                )}
              </>
            ) : (
              <div className="text-xs font-mono text-gray-600">No sync data</div>
            )}
          </div>
        </Panel>

        {/* Configuration Panel */}
        <Panel color={COLORS.cyan} title="Configuration">
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <label className="text-xs text-gray-500 uppercase">Adapter:</label>
              <select
                value={selectedAdapter}
                onChange={(e) => setSelectedAdapter(e.target.value)}
                className="flex-1 bg-black/60 border border-gray-700 rounded px-3 py-2 font-mono text-sm text-cyan-400 focus:outline-none focus:border-cyan-500"
                disabled={status.connected}
              >
                {adapters.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
              </select>
            </div>
          </div>
        </Panel>

        {/* Actions Panel */}
        <Panel color={COLORS.cyan} title="Actions">
          <div className="flex flex-wrap gap-3">
            <ActionButton
              label="Connect"
              onClick={handleConnect}
              disabled={status.connected || status.is_busy}
            />
            <ActionButton
              label="Authenticate"
              onClick={handleAuth}
              disabled={!status.connected || status.authenticated || status.is_busy}
            />
            <ActionButton
              label="Sync Time"
              onClick={handleSyncTime}
              disabled={!status.authenticated || status.is_busy}
            />
            <ActionButton
              label="Disconnect"
              onClick={handleDisconnect}
              disabled={!status.connected || status.is_busy}
              color={COLORS.red}
            />
          </div>
        </Panel>
      </div>

      {/* Live Heartbeat Display */}
      {(isHeartbeatActive || heartbeat) && (
        <Panel color={COLORS.cyan} title="♥ Live Heartbeat" className="mb-8">
          <div className="flex items-center gap-6">
            {/* BPM Display */}
            <div className="flex flex-col items-center">
              <div className="text-5xl font-mono font-bold text-cyan-400 tabular-nums">
                {heartbeat ? Math.round(heartbeat.bpm) : '--'}
              </div>
              <div className="text-xs text-cyan-600 uppercase tracking-wider">BPM</div>
            </div>

            {/* Real-time Chart */}
            <div className="flex-1 bg-slate-900/50 rounded-lg p-3 border border-cyan-900/30">
              <HeartbeatChart history={heartbeatHistory} />
              {heartbeatHistory.length < 2 && (
                <div className="text-xs text-gray-500 font-mono text-center py-6">
                  Waiting for data...
                </div>
              )}
            </div>

            {/* Stats */}
            <div className="flex flex-col gap-2 text-right">
              <div className="font-mono">
                <span className="text-gray-500 text-xs">IBI </span>
                <span className="text-green-400">{heartbeat?.ibi || '--'}</span>
                <span className="text-gray-600 text-xs">ms</span>
              </div>
              <div className="font-mono">
                <span className="text-gray-500 text-xs">CNT </span>
                <span className="text-emerald-400">#{heartbeat?.count || 0}</span>
              </div>
              <div className="font-mono text-xs text-gray-600">
                {heartbeatHistory.length > 0 && (
                  <>avg: {Math.round(heartbeatHistory.reduce((a, b) => a + b, 0) / heartbeatHistory.length)}</>
                )}
              </div>
            </div>

            {/* Stop Button */}
            <ActionButton
              label={isHeartbeatActive ? '■ Stop' : '▶ Start'}
              onClick={handleHeartbeat}
              disabled={!status.authenticated || (status.is_busy && !isHeartbeatActive)}
              color={isHeartbeatActive ? COLORS.red : COLORS.cyan}
            />
          </div>
        </Panel>
      )}

      {/* Update Ring - Main action */}
      <Panel color={COLORS.green} title="Sync Data" subtitle="Fetch events from ring" className="mb-8">
        <div className="flex items-center gap-4 flex-wrap">
          <ActionButton
            label="⟳ Update Ring"
            onClick={handleUpdateRing}
            disabled={!status.authenticated || status.is_busy}
            color={COLORS.green}
          />
          <ActionButton
            label="↻ Full Sync"
            onClick={() => send('full-sync')}
            disabled={!status.authenticated || status.is_busy}
            color={COLORS.orange}
          />
          <span className="text-xs text-gray-500 font-mono">
            Update = incremental, Full = clear &amp; fetch all
          </span>
          {progress && (
            <div className="flex-1 min-w-48">
              <div className="text-xs text-gray-500 mb-1">{progress.label}</div>
              <ProgressBar value={progress.current} max={progress.total} color={COLORS.cyan} />
            </div>
          )}
        </div>
      </Panel>

      {/* Parse Events - Convert raw events to protobuf */}
      <Panel color={COLORS.orange} title="Parse Events" subtitle="Reverse-sort + native parser" className="mb-8">
        <div className="flex items-center gap-4">
          <ActionButton
            label="Parse Events"
            onClick={() => send('parse', {})}
            disabled={status.is_busy}
            color={COLORS.orange}
          />
          <span className="text-xs text-gray-500 font-mono">
            Dedup + reverse date order → native parser (detects all nights)
          </span>
        </div>
      </Panel>

      {/* Heartbeat Button (when not active) */}
      {!isHeartbeatActive && !heartbeat && (
        <Panel color={COLORS.pink} title="Heartbeat Monitoring" className="mb-8">
          <div className="flex items-center gap-4">
            <ActionButton
              label="Start Heartbeat"
              onClick={handleHeartbeat}
              disabled={!status.authenticated || status.is_busy}
              color={COLORS.pink}
            />
            <span className="text-xs text-gray-500">Stream real-time heart rate from the ring</span>
          </div>
        </Panel>
      )}

      {/* Advanced Operations */}
      <Panel color={COLORS.red} title="Advanced Operations" subtitle="Use with caution" className="mb-8">
        <div className="flex flex-wrap gap-3">
          <ActionButton
            label="Pair Ring"
            onClick={handlePair}
            disabled={status.is_busy}
            color={COLORS.orange}
          />
          <ActionButton
            label="Unpair Ring"
            onClick={handleUnpair}
            disabled={status.is_busy}
            color={COLORS.orange}
          />
          <ActionButton
            label="Factory Reset"
            onClick={handleFactoryReset}
            disabled={!status.connected || status.is_busy}
            color={COLORS.red}
          />
        </div>

        {/* Set Auth Key */}
        <div className="mt-4 pt-4 border-t border-gray-800">
          <label className="text-xs text-gray-500 block mb-2">Set Auth Key (32 hex chars)</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={authKeyInput}
              onChange={(e) => setAuthKeyInput(e.target.value)}
              placeholder="e.g. 0123456789abcdef0123456789abcdef"
              className="flex-1 bg-black/60 border border-gray-700 rounded px-3 py-2 font-mono text-sm text-white focus:outline-none focus:border-orange-500"
              maxLength={32}
            />
            <ActionButton
              label="Set Key"
              onClick={handleSetAuthKey}
              disabled={!status.connected || status.is_busy || authKeyInput.replace(/\s/g, '').length !== 32}
              color={COLORS.orange}
            />
          </div>
        </div>

        <p className="text-xs text-gray-500 mt-3">
          Pair requires ring in pairing mode. Unpair removes Bluetooth bond. Factory reset erases ALL ring data.
        </p>
      </Panel>

      {/* Output Console */}
      <Panel color={COLORS.cyan} title="Output Console">
        <div className="flex justify-end mb-3">
          <button
            onClick={clearLogs}
            className="text-xs text-gray-500 hover:text-cyan-400 font-mono transition-colors"
          >
            [Clear]
          </button>
        </div>
        <TerminalOutput logs={logs} />
      </Panel>

      {/* Confirmation Dialog */}
      {confirmDialog && (
        <ConfirmDialog
          action={confirmDialog}
          onConfirm={confirmAction}
          onCancel={() => setConfirmDialog(null)}
        />
      )}
    </div>
  )
}

// ============== App Container ==============

function AppContent() {
  return (
    <div className="min-h-screen relative" style={{ backgroundColor: '#030712' }}>
      {/* Grid background */}
      <div
        className="fixed inset-0 pointer-events-none opacity-30"
        style={{
          backgroundImage: `
            linear-gradient(${COLORS.cyan}08 1px, transparent 1px),
            linear-gradient(90deg, ${COLORS.cyan}08 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px'
        }}
      />
      {/* Radial glow */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse at 50% 0%, ${COLORS.cyan}08 0%, transparent 50%)`
        }}
      />
      <Navigation />
      <main className="relative z-10">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/sleep-stages" element={<SleepStagesDashboard />} />
          <Route path="/hrv" element={<HRVDashboardPage />} />
          <Route path="/activity" element={<ActivityDashboard />} />
          <Route path="/raw" element={<RawDataBrowser />} />
          <Route path="/ring-control" element={<RingControlPage />} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AppContent />
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
