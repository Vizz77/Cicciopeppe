import { clientsQuery, exploitsQuery, toggleWorkerExploit, useServiceSolver, workersPoolQuery } from "@/utils/queries";
import { secondDurationToString } from "@/utils/time";
import { Badge, Box, Divider, Grid, Group, Paper, ScrollArea, Stack, Switch, Table, Text, Title, Tooltip } from "@mantine/core";
import { FaArchive, FaRobot, FaServer } from "react-icons/fa";

export const WorkersScreen = () => {
    const pool = workersPoolQuery();
    const exploits = exploitsQuery();
    const clients = clientsQuery();
    const getServiceName = useServiceSolver();

    const clientRows = pool.data?.clients?.map((client: any) => {
        const clientInfo = clients.data?.find((c: any) => c.id === client.id);
        const displayName = clientInfo?.name || client.id;
        const os = clientInfo?.os || "Unknown OS";
        const arch = clientInfo?.arch || "Unknown Arch";
        const version = clientInfo?.version || "n/a";

        return (
            <Table.Tr key={client.sid}>
                <Table.Td>
                    <Group gap="sm">
                        <FaRobot color="teal" size={18} />
                        <Box>
                            <Text size="sm" fw={500}>{displayName}</Text>
                            <Text size="xs" c="dimmed">Active Worker</Text>
                        </Box>
                    </Group>
                </Table.Td>
                <Table.Td>
                    <Badge color="blue" variant="light">{client.queue_size} Slots</Badge>
                </Table.Td>
                <Table.Td>
                    <Stack gap={2}>
                        <Text size="xs" fw={700}>{os}</Text>
                        <Text size="xs" c="dimmed">{arch}</Text>
                    </Stack>
                </Table.Td>
                <Table.Td>
                    <Badge color="gray" size="sm">{version}</Badge>
                </Table.Td>
            </Table.Tr>
        );
    }) || [];

    const exploitRows = exploits.data?.map((exploit) => {
        let statusColor = "gray";
        let statusLabel = "Not Running";
        if (exploit.status === "active") {
            if (exploit.last_execution_group_by == "workers") {
                statusColor = "teal";
                statusLabel = "Workers Pool";
            } else if (exploit.last_execution_group_by) {
                statusColor = "grape";
                statusLabel = "Group";
            } else if (exploit.last_execution_by && exploit.last_execution_by !== "manual") {
                statusColor = "blue";
                statusLabel = "Standalone";
            } else {
                statusColor = "gray";
                statusLabel = "Not Running";
            }
        }

        return (
            <Table.Tr key={exploit.id}>
                <Table.Td>
                    <Stack gap={0}>
                        <Text size="sm" fw={500}>{exploit.name}</Text>
                        <Text size="xs" c="dimmed">{getServiceName(exploit.service)}</Text>
                    </Stack>
                </Table.Td>
                <Table.Td>
                    <Badge color={statusColor} variant="light" size="sm">
                        {statusLabel}
                    </Badge>
                </Table.Td>
                <Table.Td>
                    <Switch
                        checked={exploit.run_on_workers}
                        onChange={(e) => toggleWorkerExploit(exploit.id, e.currentTarget.checked)}
                        color="teal"
                        size="sm"
                    />
                </Table.Td>
            </Table.Tr>
        )
    }) || [];

    const totalSlots = pool.data?.clients?.reduce((acc: number, client: any) => acc + (client.queue_size || 0), 0) || 0;

    return (
        <Box p="md" h="calc(100vh - 110px)">
            <Grid gutter="xl" h="100%" align="stretch">
                <Grid.Col span={{ base: 12, md: 7 }}>
                    <Paper withBorder p="md" radius="md" h="100%" display="flex" style={{ flexDirection: "column" }}>
                        <Group justify="space-between" mb="md" style={{ flexShrink: 0 }}>
                            <Group>
                                <FaServer size={22} color="teal" />
                                <Title order={3}>Connected Workers</Title>
                            </Group>
                            <Group>
                                <Tooltip label="Number of active physical workers">
                                    <Badge color="teal" size="lg" variant="filled">
                                        {pool.data?.members?.length || 0} Clients
                                    </Badge>
                                </Tooltip>
                                <Tooltip label="Total concurrent exploitation slots available">
                                    <Badge color="blue" size="lg" variant="outline">
                                        {totalSlots} Total Slots
                                    </Badge>
                                </Tooltip>
                                <Tooltip label="Timeout for exploitation">
                                    <Badge color="orange" size="lg" variant="outline">
                                        {pool.data?.timeout ? secondDurationToString(pool.data.timeout) : "N/A"} Timeout
                                    </Badge>
                                </Tooltip>
                            </Group>
                        </Group>
                        <Divider mb="sm" />
                        <ScrollArea style={{ flex: 1 }}>
                            <Table verticalSpacing="sm">
                                <Table.Thead>
                                    <Table.Tr>
                                        <Table.Th>Worker ID</Table.Th>
                                        <Table.Th>Capacity</Table.Th>
                                        <Table.Th>Environment</Table.Th>
                                        <Table.Th>Version</Table.Th>
                                    </Table.Tr>
                                </Table.Thead>
                                <Table.Tbody>
                                    {clientRows.length > 0 ? clientRows : (
                                        <Table.Tr>
                                            <Table.Td colSpan={5}>
                                                <Text c="dimmed" ta="center" py="xl">No workers currently connected to the pool.</Text>
                                            </Table.Td>
                                        </Table.Tr>
                                    )}
                                </Table.Tbody>
                            </Table>
                        </ScrollArea>
                    </Paper>
                </Grid.Col>

                <Grid.Col span={{ base: 12, md: 5 }}>
                    <Paper withBorder p="md" radius="md" h="100%" display="flex" style={{ flexDirection: "column" }}>
                        <Group mb="md" style={{ flexShrink: 0 }}>
                            <FaArchive size={20} color="orange" />
                            <Title order={3}>Exploit Assignments</Title>
                        </Group>
                        <Divider mb="sm" />
                        <Text size="xs" c="dimmed" mb="md" style={{ flexShrink: 0 }}>
                            Enable exploits to allow the workers pool to execute them automatically against all teams.
                        </Text>
                        <ScrollArea style={{ flex: 1 }}>
                            <Table verticalSpacing="xs">
                                <Table.Thead>
                                    <Table.Tr>
                                        <Table.Th>Exploit / Service</Table.Th>
                                        <Table.Th>Status</Table.Th>
                                        <Table.Th>Run on Pool</Table.Th>
                                    </Table.Tr>
                                </Table.Thead>
                                <Table.Tbody>
                                    {exploitRows.length > 0 ? exploitRows : (
                                        <Table.Tr>
                                            <Table.Td colSpan={3}>
                                                <Text c="dimmed" ta="center" py="xl">No exploits defined.</Text>
                                            </Table.Td>
                                        </Table.Tr>
                                    )}
                                </Table.Tbody>
                            </Table>
                        </ScrollArea>
                    </Paper>
                </Grid.Col>
            </Grid>
        </Box>
    );
};
