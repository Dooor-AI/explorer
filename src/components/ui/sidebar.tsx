'use client'

import React from 'react'
import { Badge } from './badge'
import { cn } from '@/lib/utils'
import { LucideIcon } from 'lucide-react'

interface SidebarProps {
  children: React.ReactNode
  className?: string
}

export function Sidebar({ children, className }: SidebarProps) {
  return (
    <div className={cn(
      "w-64 bg-sidebar border-r border-sidebar-border flex flex-col",
      className
    )}>
      {children}
    </div>
  )
}

interface SidebarItemProps {
  icon: LucideIcon
  label: string
  badge?: string
  isActive?: boolean
  onClick?: () => void
}

export function SidebarItem({ icon: Icon, label, badge, isActive, onClick }: SidebarItemProps) {
  return (
    <div className="px-3">
      <button
        onClick={onClick}
        className={cn(
          "flex items-center gap-3 px-3 py-1 text-sm font-medium transition-all duration-200 text-left cursor-pointer select-none w-full rounded-[6px]",
          isActive 
            ? "bg-sidebar-primary text-sidebar-primary-foreground" 
            : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
        )}
      >
        <Icon className="w-4 h-4 shrink-0" />
        <span className="flex-1 select-text">{label}</span>
        {badge && (
          <Badge variant="secondary" className="text-xs px-2 py-0.5">
            {badge}
          </Badge>
        )}
      </button>
    </div>
  )
}

interface SidebarSectionProps {
  title: string
  children: React.ReactNode
}

export function SidebarSection({ title, children }: SidebarSectionProps) {
  return (
    <div className="py-2">
      <h3 className="px-3 text-xs font-semibold text-sidebar-foreground/70 uppercase tracking-wider mb-2 select-text">
        {title}
      </h3>
      <div className="space-y-1">
        {children}
      </div>
    </div>
  )
}

interface SidebarHeaderProps {
  title: string
  subtitle?: string
  logo?: React.ReactNode
}

export function SidebarHeader({ title, subtitle, logo }: SidebarHeaderProps) {
  return (
    <div className="p-6 border-b border-sidebar-border">
      <div className="items-center gap-1 -mt-5">
        {logo}
        <div className="flex-1 -mt-2">
          <h2 className="text-lg font-semibold text-sidebar-foreground select-text">{title}</h2>
          {subtitle && (
            <p className="text-sm text-sidebar-foreground/70 select-text">{subtitle}</p>
          )}
        </div>
      </div>
    </div>
  )
}

export { type SidebarItemProps, type SidebarSectionProps, type SidebarProps } 