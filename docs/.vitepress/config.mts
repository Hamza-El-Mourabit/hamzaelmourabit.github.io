import { defineConfig } from 'vitepress'

export default defineConfig({
    title: "LWa7ch's Blogs",
    description: "Cybersecurity & AI Engineering - Technical Write-ups",
    cleanUrls: false,
    themeConfig: {
        logo: '/logo.png',
        nav: [
            { text: 'Home', link: '/' },
            { text: 'Write-ups', link: '/posts/dirty-laundry' },
            { text: 'About', link: '/about' }
        ],
        sidebar: [
            {
                text: 'CTF Write-ups',
                items: [
                    { text: 'Pokedex (UAF Heap)', link: '/posts/pokedex' },
                    { text: 'Talking Mirror (Format String)', link: '/posts/talking-mirror' },
                    { text: 'Dirty Laundry (Ret2Libc)', link: '/posts/dirty-laundry' },
                    { text: 'UltraCTF Architecture', link: '/posts/ultra-ctf' }
                ]
            }
        ],
        socialLinks: [
            { icon: 'github', link: 'https://github.com' }
        ],
        footer: {
            message: 'Released under the MIT License.',
            copyright: 'Copyright © 2026-present LWa7ch'
        },
        search: {
            provider: 'local'
        }
    },
    appearance: true
})
