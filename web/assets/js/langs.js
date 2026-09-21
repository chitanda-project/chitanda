const supportLangs = [
    {
        name: '汉语',
        value: 'zh-Hans',
        icon: '🇨🇳',
    },
    {
        name: 'English',
        value: 'en-US',
        icon: '🇺🇸',
    },
    {
        name: 'فارسی',
        value: 'fa-IR',
        icon: '🇮🇷',
    },
    {
        name: 'Русский',
        value: 'ru-RU',
        icon: '🇷🇺',
    },
    {
        name: 'Tiếng Việt',
        value: 'vi-VN',
        icon: '🇻🇳',
    },
    {
        name: 'Español',
        value: 'es-ES',
        icon: '🇪🇸',
    },
    {
        name: 'Indonesian',
        value: 'id-ID',
        icon: '🇮🇩',
    },
    {
        name: 'Український',
        value: 'uk-UA',
        icon: '🇺🇦',
    },
];

function normalizeLang(lang) {
    if (!lang) return 'zh-Hans';
    const lower = lang.toLowerCase();
    if (lower.startsWith('zh')) return 'zh-Hans';
    if (lower.startsWith('en')) return 'en-US';
    if (lower.startsWith('fa')) return 'fa-IR';
    if (lower.startsWith('ru')) return 'ru-RU';
    if (lower.startsWith('vi')) return 'vi-VN';
    if (lower.startsWith('es')) return 'es-ES';
    if (lower.startsWith('id')) return 'id-ID';
    if (lower.startsWith('uk')) return 'uk-UA';
    for (const l of supportLangs) {
        if (l.value.toLowerCase() === lower) {
            return l.value;
        }
    }
    return 'zh-Hans';
}

function getLang() {
    let lang = getCookie('lang');

    if (!lang) {
        let navLang = '';
        if (window.navigator) {
            navLang = window.navigator.language || window.navigator.userLanguage || '';
        }
        lang = normalizeLang(navLang);
        setCookie('lang', lang, 150);
        window.location.reload();
    }

    return lang;
}

function setLang(lang) {
    lang = normalizeLang(lang);
    setCookie('lang', lang, 150);
    window.location.reload();
}

function isSupportLang(lang) {
    for (l of supportLangs) {
        if (l.value === lang) {
            return true;
        }
    }

    return false;
}

