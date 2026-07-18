/// <reference types="vite/client" />

interface ImportMetaEnv {
    /** Веб-кабинет для продления подписки */
    readonly VITE_RENEW_WEB_URL?: string
    /** Telegram-бот для продления подписки */
    readonly VITE_RENEW_BOT_URL?: string
}

interface ImportMeta {
    readonly env: ImportMetaEnv
}
