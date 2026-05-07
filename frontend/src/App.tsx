import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css'
import '@mantine/charts/styles.css'
import '@mantine/dates/styles.css';
import '@mantine/dropzone/styles.css';
import '@mantine/code-highlight/styles.css';

import { notifications, Notifications } from '@mantine/notifications';
import { LoadingOverlay, MantineProvider, Title } from '@mantine/core';
import { LoginProvider } from '@/components/LoginProvider';
import { Routes, Route, BrowserRouter } from "react-router";
import { useGlobalStore, useTokenStore } from './utils/stores';
import { HomePage } from './components/screens/HomePage';
import { MainLayout } from './components/MainLayout';
import { useEffect, useRef } from 'react';
import { DEBOUNCED_SOCKET_IO_CHANNELS, socket_io, SOCKET_IO_CHANNELS, sockIoChannelToQueryKeys } from './utils/net';
import { useQueryClient } from '@tanstack/react-query';
import { useDebouncedCallback } from '@mantine/hooks'
import { CodeHighlightAdapterProvider, stripShikiCodeBlocks } from '@mantine/code-highlight';
import { CodeHighlightAdapter } from 'node_modules/@mantine/code-highlight/lib/CodeHighlightProvider/CodeHighlightProvider';
import { exploitsQuery, statsQuery, statusQuery } from './utils/queries';

// Shiki requires async code to load the highlighter
async function loadShiki() {
  const { createHighlighter } = await import('shiki');
  const shiki = await createHighlighter({
    langs: ['python'],
    themes: ['one-dark-pro', 'one-light']
  });

  return shiki;
}

// Pass this adapter to CodeHighlightAdapterProvider component
export const customShikiAdapter: CodeHighlightAdapter = {
  // loadContext is called on client side to load shiki highlighter
  // It is required to be used if your library requires async initialization
  // The value returned from loadContext is passed to createHighlighter as ctx argument
  loadContext: loadShiki,

  getHighlighter: (ctx) => {
    if (!ctx) {
      return ({ code }) => ({ highlightedCode: code, isHighlighted: false });
    }

    return ({ code, language, colorScheme }) => ({
      isHighlighted: true,
      // stripShikiCodeBlocks removes <pre> and <code> tags from highlighted code
      highlightedCode: stripShikiCodeBlocks(
        ctx.codeToHtml(code, {
          lang: language,
          theme: colorScheme === 'dark' ? 'one-dark-pro' : 'one-light',
        })
      ),
    });
  },
};

export default function App() {

    const queryClient = useQueryClient()
    const { setErrorMessage, loading:loadingStatus } = useGlobalStore()
    const { loginToken } = useTokenStore()
    const stats = statsQuery()
    const status = statusQuery()
    const exploits = exploitsQuery()

    // Debug notification
    const lastDebugTickNotified = useRef<number | null>(null)
    const lastWarningTickNotified = useRef<Record<string, number>>({})
    const lastErrorTickNotified = useRef<Record<string, number>>({})

    const debouncedCalls = DEBOUNCED_SOCKET_IO_CHANNELS.map((channel) => (
        useDebouncedCallback(() => {
            sockIoChannelToQueryKeys(channel).forEach((data) =>
                queryClient.invalidateQueries({ queryKey: data })
            )
        }, 3000)
    ))

    useEffect(() => {
        if (!stats.data || !exploits.data || !status.data?.services) return
        if (stats.data.ticks.length == 0) return

        const latestTick = stats.data.ticks[stats.data.ticks.length - 1]
        if (!latestTick) return

        const calcServicesStats = (tick: typeof latestTick) => {
            const serviceStats : Record<string, {name : string, ok : number , total : number }> = {}
            status.data?.services?.forEach((service) => {
                serviceStats[service.id] = {
                    name: service.name,
                    ok: 0,
                    total: 0,
                }
            })

            Object.entries(tick.exploits).forEach(([exploitId, exploitStats]) => {
                const exploit = exploits.data.find((item) => item.id === exploitId)
                if (!exploit || !exploit.service || !exploitStats) return

                const service = serviceStats[exploit.service]
                if (!service) return

                service.ok += exploitStats.flags.ok
                service.total += exploitStats.flags.tot
            })

            return serviceStats
        }

        // Debug notification every 2 ticks
        if(latestTick.tick % 2 == 0 && lastDebugTickNotified.current !== latestTick.tick) {
            const serviceStats = calcServicesStats(latestTick)

            const message = Object.values(serviceStats)
                .map((service) => `${service.name}: ${service.ok}/${service.total} ok flags`)
                .join("\n")

            notifications.show({
                title: `Debug stats - tick ${latestTick.tick}`,
                message: <span style={{ whiteSpace: "pre-line" }}>{message}</span>,
                color: "blue",
                autoClose: 8000,
            })

            lastDebugTickNotified.current = latestTick.tick
        }

        // Warning if a service is stealing less flags than the previous 5 ticks average
        if (stats.data.ticks.length >= 6) {
            const previousTicks = stats.data.ticks.slice(-6, -1)
            const currentServiceStats = calcServicesStats(latestTick)
            const previousServicesStats = previousTicks.map((tick) => calcServicesStats(tick))

            Object.entries(currentServiceStats).forEach(([serviceId, service]) => {
                const previousTotal = previousServicesStats.reduce((tot, tickStats) => {
                    return tot + (tickStats[serviceId]?.ok ?? 0)
                }, 0)
                const previousAvg = previousTotal / previousTicks.length

                if (previousAvg <= 0) return
                if (service.ok >= previousAvg) return
                if (lastWarningTickNotified.current[serviceId] === latestTick.tick) return

                notifications.show({
                    title: `Low flags for ${service.name}`,
                    message: `Tick ${latestTick.tick}: ${service.ok} ok flags, previous 5 ticks average: ${previousAvg.toFixed(1)}`,
                    color: "yellow",
                    autoClose: 10000,
                })

                lastWarningTickNotified.current[serviceId] = latestTick.tick
            })
        }

        // Error if an exploit executes for 3 ticks and returns 0 ok flags
        if (stats.data.ticks.length >= 3) {
            const last3Ticks = stats.data.ticks.slice(-3)

            exploits.data.forEach((exploit) => {
                const failedFor3Ticks = last3Ticks.every((tick) => {
                    const exploitStats = tick.exploits[exploit.id]
                    return (exploitStats?.attacks.tot ?? 0) > 0 && (exploitStats?.flags.ok ?? 0) == 0
                })

                if (!failedFor3Ticks) return
                if (lastErrorTickNotified.current[exploit.id] === latestTick.tick) return

                notifications.show({
                    title: `Exploit ${exploit.name} returned 0 flags`,
                    message: `The exploit returned 0 ok flags for 3 ticks in a row.(SYS ADMIN FIX IT PLS PLS PLS !!!)`,
                    color: "red",
                    autoClose: false,
                })

                lastErrorTickNotified.current[exploit.id] = latestTick.tick
            })
        }
    }, [stats.data, exploits.data, status.data?.services])

    useEffect(() => {
        SOCKET_IO_CHANNELS.forEach((channel) => {
            socket_io.on(channel, (_data) => {
                if (DEBOUNCED_SOCKET_IO_CHANNELS.includes(channel)) {
                    debouncedCalls[DEBOUNCED_SOCKET_IO_CHANNELS.indexOf(channel)]()
                } else {
                    sockIoChannelToQueryKeys(channel).forEach((data) =>
                        queryClient.invalidateQueries({ queryKey: data })
                    )
                }
            })
        })
        socket_io.on("connect_error", (err) => {
            setErrorMessage({
                title: "BACKEND SEEMS DOWN!",
                message: "Can't connect to backend APIs: " + err.message,
                color: "red"
            })
        });
        
        let first_time = true
        socket_io.on("connect", () => {
            if (socket_io.connected) {
                setErrorMessage(null)
                if (!first_time) {
                    queryClient.resetQueries({ queryKey: [] })
                    notifications.show({
                        id: "connected-backend",
                        title: "Connected to the backend!",
                        message: "Successfully connected to the backend!",
                        color: "blue",
                        icon: "🚀",
                    })
                }
            }
            first_time = false
        });
        return () => {
            SOCKET_IO_CHANNELS.forEach((channel) => {
                socket_io.off(channel)
            })
            socket_io.off("connect_error")
        }
    }, [])


    useEffect(() => {
        socket_io.auth = { token: loginToken }
        socket_io.disconnect()
        socket_io.connect()
    }, [loginToken])

    return (
        <MantineProvider defaultColorScheme='dark'>
            <CodeHighlightAdapterProvider adapter={customShikiAdapter}>
                <Notifications />
                <LoadingOverlay visible={loadingStatus || status.isLoading} zIndex={10} overlayProps={{ radius: "sm", blur: 2 }} />
                <LoginProvider>
                    <BrowserRouter>
                        <Routes>
                            <Route path="/" element={<HomePage />} />
                            <Route path="/:page" element={<HomePage />} />
                            <Route path="*" element={<MainLayout><Title order={1}>404 Not Found</Title></MainLayout>} />
                        </Routes>
                    </BrowserRouter>
                </LoginProvider>
            </CodeHighlightAdapterProvider>
        </MantineProvider>
    )
}
