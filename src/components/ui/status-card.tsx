import React from 'react'
import { Card, CardContent } from './card'
import { Badge } from './badge'
import { cn } from '@/lib/utils'
import { 
  MdCheckCircle, 
  MdError, 
  MdWarning, 
  MdInfo,
  MdRefresh,
  MdCircle
} from 'react-icons/md'

interface StatusCardProps {
  status: 'success' | 'error' | 'warning' | 'info' | 'loading'
  title?: string
  message: string
  details?: string
  className?: string
}

export function StatusCard({ 
  status, 
  title, 
  message, 
  details, 
  className 
}: StatusCardProps) {
  const getStatusStyles = () => {
    switch (status) {
      case 'success':
        return {
          cardClass: 'border-tee-success/30 bg-gradient-to-br from-green-950/20 to-background-card shadow-glow-green',
          badgeVariant: 'success' as const,
          icon: <MdCheckCircle className="w-5 h-5" />,
          iconClass: 'text-tee-success'
        }
      case 'error':
        return {
          cardClass: 'border-tee-error/30 bg-gradient-to-br from-red-950/20 to-background-card shadow-glow-red',
          badgeVariant: 'destructive' as const,
          icon: <MdError className="w-5 h-5" />,
          iconClass: 'text-tee-error'
        }
      case 'warning':
        return {
          cardClass: 'border-tee-warning/30 bg-gradient-to-br from-yellow-950/20 to-background-card',
          badgeVariant: 'warning' as const,
          icon: <MdWarning className="w-5 h-5" />,
          iconClass: 'text-tee-warning'
        }
      case 'info':
        return {
          cardClass: 'border-tee-info/30 bg-gradient-to-br from-blue-950/20 to-background-card shadow-glow',
          badgeVariant: 'info' as const,
          icon: <MdInfo className="w-5 h-5" />,
          iconClass: 'text-tee-info'
        }
      case 'loading':
        return {
          cardClass: 'border-border bg-background-card loading',
          badgeVariant: 'secondary' as const,
          icon: <MdRefresh className="w-5 h-5 animate-spin" />,
          iconClass: 'text-foreground-secondary'
        }
      default:
        return {
          cardClass: 'border-border bg-background-card',
          badgeVariant: 'secondary' as const,
          icon: <MdCircle className="w-5 h-5" />,
          iconClass: 'text-foreground-secondary'
        }
    }
  }

  const { cardClass, badgeVariant, icon, iconClass } = getStatusStyles()

  return (
    <Card className={cn(cardClass, 'animate-fade-in', className)}>
      <CardContent className="p-6">
        <div className="flex items-start gap-4">
          <div className={cn("flex-shrink-0", iconClass)} role="img" aria-label={status}>
            {icon}
          </div>
          <div className="flex-1 space-y-3">
            <div className="flex items-center gap-3">
              {title && (
                <h3 className="font-semibold text-foreground text-lg">{title}</h3>
              )}
              <Badge variant={badgeVariant} className="text-2xs font-medium">
                {status.toUpperCase()}
              </Badge>
            </div>
            <p className="text-foreground-secondary leading-relaxed">{message}</p>
            {details && (
              <div className="mt-4">
                <pre className="text-xs text-foreground-muted bg-background-secondary/50 p-4 rounded-lg overflow-x-auto font-mono border border-border leading-relaxed whitespace-pre-wrap">
                  {details}
                </pre>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export default StatusCard 