import { clientsQuery, exploitsQuery, groupsQuery, useServiceSolver } from "@/utils/queries";
import { secondDurationToString } from "@/utils/time";
import { Badge, Box, Divider, Grid, Group, Paper, ScrollArea, Stack, Table, Text, Title, Tooltip, NavLink, Tabs, Button } from "@mantine/core";
import { FaArchive, FaRobot, FaServer } from "react-icons/fa";
import { MdGroups } from "react-icons/md";
import { useState } from "react";
import { AddButton, DeleteButton, EditButton } from "@/components/inputs/Buttons";
import { AddGroupModal } from "@/components/modals/AddGroupModal";
import { EditGroupModal } from "@/components/modals/EditGroupModal";
import { DeleteGroupModal } from "@/components/modals/DeleteGroupModal";
import { ManageExploitsModal } from "@/components/modals/ManageExploitsModal";
import { AttackGroup } from "@/utils/types";

export const WorkersScreen = () => {
    const groups = groupsQuery();
    const exploits = exploitsQuery();
    const clients = clientsQuery();
    const getServiceName = useServiceSolver();
    const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null);
    const [addGroupOpened, setAddGroupOpened] = useState(false);
    const [editGroup, setEditGroup] = useState<AttackGroup | undefined>();
    const [deleteGroup, setDeleteGroup] = useState<AttackGroup | undefined>();
    const [manageExploitsGroup, setManageExploitsGroup] = useState<AttackGroup | undefined>();
    const [activeTab, setActiveTab] = useState<string | null>("workers");

    const activeGroup = groups.data?.find(g => g.id === selectedGroupId) || groups.data?.[0];

    const clientRows = activeGroup?.members?.map((client: any) => {
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

    const exploitRows = activeGroup?.exploits?.map((exploitId: string) => {
        const exploit = exploits.data?.find(e => e.id === exploitId);
        if (!exploit) return null;
        let statusColor = "gray";
        let statusLabel = "Not Running";
        if (exploit.status === "active") {
            if (exploit.last_execution_group_by === activeGroup.id) {
                statusColor = "teal";
                statusLabel = "Running Here";
            } else if (exploit.last_execution_group_by) {
                statusColor = "grape";
                statusLabel = "Other Group";
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
            </Table.Tr>
        )
    }) || [];

    const totalSlots = activeGroup?.members?.reduce((acc: number, client: any) => acc + (client.queue_size || 0), 0) || 0;

    return (
        <Box p="md" h="calc(100vh - 110px)">
            <Grid gutter="xl" h="100%" align="stretch">
                <Grid.Col span={{ base: 12, md: 3 }}>
                    <Paper withBorder p="md" radius="md" h="100%" display="flex" style={{ flexDirection: "column" }}>
                        <Group justify="space-between" mb="md">
                            <Group>
                                <MdGroups size={22} color="teal" />
                                <Title order={3}>Attack Groups</Title>
                            </Group>
                            <AddButton onClick={() => setAddGroupOpened(true)} />
                        </Group>
                        <Divider mb="sm" />
                        <ScrollArea style={{ flex: 1 }}>
                            {groups.data?.map(g => (
                                <NavLink
                                    key={g.id}
                                    active={activeGroup?.id === g.id}
                                    onClick={() => setSelectedGroupId(g.id)}
                                    label={g.name}
                                    description={`${g.members?.length || 0} Workers`}
                                    rightSection={<Badge color={g.status === "active" ? "teal" : "gray"}>{g.status}</Badge>}
                                />
                            ))}
                            {(!groups.data || groups.data.length === 0) && (
                                <Text c="dimmed" ta="center" py="xl">No groups found.</Text>
                            )}
                        </ScrollArea>
                    </Paper>
                </Grid.Col>

                <Grid.Col span={{ base: 12, md: 9 }}>
                    {activeGroup ? (
                        <Paper withBorder p="md" radius="md" h="100%" display="flex" style={{ flexDirection: "column" }}>
                            <Group justify="space-between" mb="md" style={{ flexShrink: 0 }}>
                                <Group>
                                    <FaServer size={22} color="teal" />
                                    <Title order={3}>{activeGroup.name}</Title>
                                    {activeGroup.id !== "00000000-0000-0000-0000-000000000000" && (
                                        <>
                                            <EditButton onClick={() => setEditGroup(activeGroup)} />
                                            <DeleteButton onClick={() => setDeleteGroup(activeGroup)} />
                                        </>
                                    )}
                                </Group>
                                <Group>
                                    <Tooltip label="Number of active physical workers">
                                        <Badge color="teal" size="lg" variant="filled">
                                            {activeGroup.members?.length || 0} Clients
                                        </Badge>
                                    </Tooltip>
                                    <Tooltip label="Total concurrent exploitation slots available">
                                        <Badge color="blue" size="lg" variant="outline">
                                            {totalSlots} Total Slots
                                        </Badge>
                                    </Tooltip>
                                    <Tooltip label="Timeout for exploitation">
                                        <Badge color="orange" size="lg" variant="outline">
                                            {activeGroup.timeout ? secondDurationToString(activeGroup.timeout) : "N/A"} Timeout
                                        </Badge>
                                    </Tooltip>
                                </Group>
                            </Group>
                            <Divider mb="sm" />

                            <Tabs value={activeTab} onChange={setActiveTab} style={{ flex: 1, display: "flex", flexDirection: "column" }}>
                                {/* Header Row: Tabs on the left, Button on the right */}
                                <Group justify="space-between" align="center" style={{ borderBottom: "1px solid var(--mantine-color-default-border)" }}>
                                    <Tabs.List style={{ borderBottom: "none" }}>
                                        <Tabs.Tab value="workers" leftSection={<FaRobot />}>Connected Workers</Tabs.Tab>
                                        <Tabs.Tab value="exploits" leftSection={<FaArchive />}>Assigned Exploits</Tabs.Tab>
                                    </Tabs.List>

                                    {/* Only show the button when the Exploits tab is active */}
                                    <Button
                                        variant="light"
                                        size="xs"
                                        mr="sm"
                                        mb="sm"
                                        onClick={() => setManageExploitsGroup(activeGroup)}
                                        leftSection={<FaArchive size={12} />}
                                    >
                                        Manage Exploits
                                    </Button>

                                </Group>

                                <Tabs.Panel value="workers" style={{ flex: 1, overflow: "hidden", paddingTop: "10px" }}>
                                    <ScrollArea h="100%">
                                        <Table verticalSpacing="sm">
                                            <Table.Thead>
                                                <Table.Tr>
                                                    <Table.Th>Worker Name</Table.Th>
                                                    <Table.Th>Capacity</Table.Th>
                                                    <Table.Th>Environment</Table.Th>
                                                    <Table.Th>Version</Table.Th>
                                                </Table.Tr>
                                            </Table.Thead>
                                            <Table.Tbody>
                                                {clientRows.length > 0 ? clientRows : (
                                                    <Table.Tr>
                                                        <Table.Td colSpan={5}>
                                                            <Text c="dimmed" ta="center" py="xl">No workers currently connected to this group.</Text>
                                                        </Table.Td>
                                                    </Table.Tr>
                                                )}
                                            </Table.Tbody>
                                        </Table>
                                    </ScrollArea>
                                </Tabs.Panel>

                                <Tabs.Panel value="exploits" style={{ flex: 1, overflow: "hidden", paddingTop: "10px", display: "flex", flexDirection: "column" }}>
                                    <ScrollArea h="100%">
                                        <Table verticalSpacing="xs">
                                            <Table.Thead>
                                                <Table.Tr>
                                                    <Table.Th>Exploit / Service</Table.Th>
                                                    <Table.Th>Status</Table.Th>
                                                </Table.Tr>
                                            </Table.Thead>
                                            <Table.Tbody>
                                                {exploitRows.length > 0 ? exploitRows : (
                                                    <Table.Tr>
                                                        <Table.Td colSpan={2}>
                                                            {/* Actionable Empty State */}
                                                            <Stack align="center" py="xl" gap="sm">
                                                                <Text c="dimmed">No exploits assigned to this group yet.</Text>
                                                                <Button size="sm" variant="outline" onClick={() => setManageExploitsGroup(activeGroup)}>
                                                                    Assign Exploits
                                                                </Button>
                                                            </Stack>
                                                        </Table.Td>
                                                    </Table.Tr>
                                                )}
                                            </Table.Tbody>
                                        </Table>
                                    </ScrollArea>
                                </Tabs.Panel>
                            </Tabs>
                        </Paper>
                    ) : (
                        <Paper withBorder p="md" radius="md" h="100%" display="flex" style={{ flexDirection: "column", justifyContent: "center", alignItems: "center" }}>
                            <Text c="dimmed">Select a group to view details.</Text>
                        </Paper>
                    )}
                </Grid.Col>
            </Grid>
            <AddGroupModal opened={addGroupOpened} onClose={() => setAddGroupOpened(false)} />
            <EditGroupModal group={editGroup} onClose={() => setEditGroup(undefined)} />
            <DeleteGroupModal group={deleteGroup} onClose={() => setDeleteGroup(undefined)} />
            <ManageExploitsModal group={manageExploitsGroup} onClose={() => setManageExploitsGroup(undefined)} />
        </Box>
    );
};
