import { type ReactNode } from 'react'
import { ConfigDrawer } from '@/components/config-drawer'
import { Header } from '@/components/layout/header'
import { Main } from '@/components/layout/main'
import { Search } from '@/components/search'
import { ThemeSwitch } from '@/components/theme-switch'

type PageProps = {
  title: string
  description?: ReactNode
  /** Botones a la derecha del título. */
  actions?: ReactNode
  /** Contenido extra en la barra superior (a la izquierda del buscador). */
  headerExtra?: ReactNode
  /** Layout fijo (la pantalla maneja su propio scroll). */
  fixed?: boolean
  children: ReactNode
}

/** Marco común de cada pantalla: barra superior (Ctrl+K, tema) + título + contenido. */
export function Page({
  title,
  description,
  actions,
  headerExtra,
  fixed,
  children,
}: PageProps) {
  return (
    <>
      <Header fixed={fixed}>
        {headerExtra}
        <div className='ms-auto flex items-center gap-2'>
          <Search placeholder='Buscar sección' />
          <ThemeSwitch />
          <ConfigDrawer />
        </div>
      </Header>
      <Main fixed={fixed}>
        <div className='mb-4 flex flex-wrap items-start justify-between gap-2'>
          <div>
            <h1 className='text-2xl font-bold tracking-tight'>{title}</h1>
            {description && (
              <p className='text-sm text-muted-foreground'>{description}</p>
            )}
          </div>
          {actions && <div className='flex items-center gap-2'>{actions}</div>}
        </div>
        {children}
      </Main>
    </>
  )
}
