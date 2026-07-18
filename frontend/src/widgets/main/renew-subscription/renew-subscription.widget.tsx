import { IconChevronRight, IconBrandTelegram, IconWorld, IconRefresh } from '@tabler/icons-react'
import { Button, Stack, Text, UnstyledButton } from '@mantine/core'
import { modals } from '@mantine/modals'

import { useCurrentLang } from '@entities/app-config-store'
import { vibrate } from '@shared/utils/vibrate'

import classes from './renew-subscription.module.css'

const LABELS = {
    en: {
        renew: 'Renew subscription',
        title: 'Renew subscription',
        subtitle: 'Choose where to continue',
        web: 'Web cabinet',
        webDesc: 'Open the payment page in your browser',
        bot: 'Telegram bot',
        botDesc: 'Renew right inside Telegram'
    },
    ru: {
        renew: 'Продлить подписку',
        title: 'Продлить подписку',
        subtitle: 'Выберите, где продолжить',
        web: 'Веб-кабинет',
        webDesc: 'Открыть страницу оплаты в браузере',
        bot: 'Telegram-бот',
        botDesc: 'Продлить прямо в Telegram'
    }
} as const

const WEB_URL = import.meta.env.VITE_RENEW_WEB_URL
const BOT_URL = import.meta.env.VITE_RENEW_BOT_URL

const openLink = (url: string) => {
    window.open(url, '_blank', 'noopener,noreferrer')
}

interface ChoiceProps {
    desc: string
    icon: React.ReactNode
    label: string
    onClick: () => void
}

const Choice = ({ icon, label, desc, onClick }: ChoiceProps) => (
    <UnstyledButton className={classes.choice} onClick={onClick}>
        <span className={classes.choiceIcon}>{icon}</span>
        <Stack gap={2} style={{ flex: 1, minWidth: 0 }}>
            <Text c="white" fw={600} size="sm">
                {label}
            </Text>
            <Text c="dimmed" size="xs">
                {desc}
            </Text>
        </Stack>
        <IconChevronRight size={16} style={{ color: 'var(--mantine-color-dark-2)' }} />
    </UnstyledButton>
)

export const RenewSubscriptionWidget = () => {
    const currentLang = useCurrentLang()
    const l = LABELS[currentLang as keyof typeof LABELS] ?? LABELS.en

    // Без хотя бы одной ссылки кнопку не показываем.
    if (!WEB_URL && !BOT_URL) return null

    const handleOpen = () => {
        vibrate('tap')

        modals.open({
            centered: true,
            title: l.title,
            classNames: {
                content: classes.modalContent,
                header: classes.modalHeader,
                title: classes.modalTitle
            },
            children: (
                <Stack gap="sm">
                    <Text c="dimmed" size="sm">
                        {l.subtitle}
                    </Text>
                    {WEB_URL && (
                        <Choice
                            desc={l.webDesc}
                            icon={<IconWorld size={20} />}
                            label={l.web}
                            onClick={() => {
                                modals.closeAll()
                                openLink(WEB_URL)
                            }}
                        />
                    )}
                    {BOT_URL && (
                        <Choice
                            desc={l.botDesc}
                            icon={<IconBrandTelegram size={20} />}
                            label={l.bot}
                            onClick={() => {
                                modals.closeAll()
                                openLink(BOT_URL)
                            }}
                        />
                    )}
                </Stack>
            )
        })
    }

    return (
        <Button
            fullWidth
            leftSection={<IconRefresh size={18} />}
            onClick={handleOpen}
            radius="xl"
            size="md"
            variant="filled"
        >
            {l.renew}
        </Button>
    )
}
