import { addGroup } from "@/utils/queries"
import { Button, Group, Modal, TextInput } from "@mantine/core"
import { useForm } from "@mantine/form"
import { notifications } from "@mantine/notifications"
import { useQueryClient } from "@tanstack/react-query"
import { useEffect } from "react"

export const AddGroupModal = ({ opened, onClose }: { opened: boolean, onClose: () => void }) => {
    const form = useForm({
        initialValues: {
            name: ""
        },
        validate: {
            name: (value) => value === "" ? "Name is required" : undefined
        }
    })

    const queryClient = useQueryClient()

    useEffect(() => {
        if (opened) {
            form.reset()
        }
    }, [opened])

    return <Modal
        opened={opened}
        onClose={onClose}
        title="Create new attack group"
        size="xl"
        centered
    >
        <form onSubmit={form.onSubmit((data) => {
            addGroup({ ...data, exploits: [] })
                .then(() => {
                    notifications.show({
                        title: `Group created!`,
                        message: "Attack group has been created successfully!",
                        color: "green",
                    })
                    queryClient.invalidateQueries({ queryKey: ["groups"] })
                }).catch((err) => {
                    notifications.show({
                        title: "Error creating group!",
                        message: err.message ?? err ?? "Unknown error",
                        color: "red",
                    })
                }).finally(() => { onClose() })
        })}>
            <TextInput
                label="Name"
                placeholder="Group name"
                withAsterisk
                {...form.getInputProps("name")}
            />
            <Group mt="xl" justify="flex-end">
                <Button onClick={onClose} color="gray">Cancel</Button>
                <Button type="submit" color="green" disabled={!form.isValid()}>Create</Button>
            </Group>
        </form>
    </Modal>
}
