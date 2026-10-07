/**
 * Happ Subscription Decryptor (JavaScript)
 * Автор: AI Assistant
 * Описание: Загружает подписку, эмулирует расшифровку crypt1-crypt5 и парсит серверы.
 */

const CONFIG = {
    // CORS-прокси для обхода блокировок (можно заменить на свой)
    CORS_PROXY: 'https://api.allorigins.win/raw?url=',
    // Таймаут запроса (мс)
    TIMEOUT: 15000
};

/**
 * Основная функция расшифровки
 * @param {string} url - URL подписки (https://...)
 * @param {string} method - Метод шифрования: 'crypt1'...'crypt5'
 * @param {string} userAgent - User-Agent (например, 'Happ/4.3.0')
 * @param {boolean} hwid - Использовать HWID (влияет на заголовки)
 * @returns {Promise<{success: boolean, raw: string, decoded: string, servers: string[], error?: string}>}
 */
async function decryptSubscription(url, method = 'crypt5', userAgent = 'Happ/4.3.0', hwid = true) {
    // 1. Валидация URL
    if (!url || !url.startsWith('http')) {
        return { success: false, raw: '', decoded: '', servers: [], error: 'Некорректный URL' };
    }

    // 2. Подготовка заголовков (эмуляция приложения Happ)
    const headers = {
        'User-Agent': userAgent,
        'Accept': '*/*'
    };
    
    if (hwid) {
        // В реальном Happ HWID передается в заголовках или параметрах.
        // Здесь мы просто добавляем заголовок для эмуляции.
        headers['X-HWID'] = '00000000-0000-0000-0000-000000000000';
    }

    // 3. Запрос через CORS-прокси
    const proxyUrl = CONFIG.CORS_PROXY + encodeURIComponent(url);
    
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), CONFIG.TIMEOUT);

        const response = await fetch(proxyUrl, {
            method: 'GET',
            headers: headers,
            signal: controller.signal
        });

        clearTimeout(timeoutId);

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const rawText = await response.text();
        let decodedText = rawText;
        let warning = '';

        // 4. Логика "расшифровки" в зависимости от метода
        switch (method) {
            case 'crypt1':
            case 'crypt4':
                // Пытаемся декодировать Base64
                try {
                    // Убираем пробелы и переносы строк
                    const cleanBase64 = rawText.replace(/\s/g, '');
                    decodedText = atob(cleanBase64);
                } catch (e) {
                    // Если не Base64, значит это уже текст
                    decodedText = rawText;
                }
                break;

            case 'crypt2':
                // URL Decode
                try {
                    decodedText = decodeURIComponent(rawText);
                } catch (e) {
                    decodedText = rawText;
                }
                break;

            case 'crypt3':
                // Raw Parse (просто оставляем как есть)
                decodedText = rawText;
                break;

            case 'crypt5':
                // RSA-4096 + ChaCha20 — это гибридное шифрование.
                // Без приватного ключа расшифровать невозможно.
                // Оставляем сырые данные и добавляем предупреждение.
                decodedText = rawText;
                warning = 'crypt5: Требуется приватный ключ приложения. Показаны сырые данные.';
                break;

            default:
                decodedText = rawText;
        }

        // 5. Парсинг серверов из decodedText
        const servers = parseServers(decodedText);

        return {
            success: true,
            raw: rawText,
            decoded: decodedText,
            servers: servers,
            warning: warning || null
        };

    } catch (error) {
        return {
            success: false,
            raw: '',
            decoded: '',
            servers: [],
            error: error.name === 'AbortError' ? 'Таймаут запроса' : error.message
        };
    }
}

/**
 * Извлекает ссылки на серверы (vless, vmess, ss) из текста
 * @param {string} text - Текст подписки
 * @returns {string[]} - Массив ссылок
 */
function parseServers(text) {
    if (!text) return [];
    
    const lines = text.split('\n');
    const servers = [];
    
    lines.forEach(line => {
        const trimmed = line.trim();
        // Проверяем популярные протоколы
        if (
            trimmed.startsWith('vless://') ||
            trimmed.startsWith('vmess://') ||
            trimmed.startsWith('ss://') ||
            trimmed.startsWith('trojan://')
        ) {
            servers.push(trimmed);
        }
    });
    
    return servers;
}

/**
 * Дополнительная утилита: Парсинг одного vless/vmess URL в объект
 * @param {string} serverUrl - Ссылка на сервер
 * @returns {object} - Разобранные параметры
 */
function parseServerUrl(serverUrl) {
    try {
        const url = new URL(serverUrl);
        const params = {};
        url.searchParams.forEach((value, key) => {
            params[key] = value;
        });

        return {
            protocol: url.protocol.replace(':', ''),
            user: url.username || null,
            host: url.hostname,
            port: url.port || '443',
            params: params,
            hash: decodeURIComponent(url.hash.replace('#', '')) || 'Без имени'
        };
    } catch (e) {
        return null;
    }
}

// ==========================================
// ПРИМЕР ИСПОЛЬЗОВАНИЯ (можно скопировать в консоль)
// ==========================================

/*
(async () => {
    const url = 'https://raw.githubusercontent.com/MK-14/EliteQ/main/EliteQ';
    
    console.log('Загрузка подписки...');
    const result = await decryptSubscription(url, 'crypt1', 'Happ/4.3.0', true);
    
    if (result.success) {
        console.log('✅ Успех!');
        console.log('Сырые данные:', result.raw.substring(0, 100) + '...');
        console.log('Расшифровано:', result.decoded.substring(0, 100) + '...');
        console.log('Найдено серверов:', result.servers.length);
        
        if (result.warning) console.warn('⚠️', result.warning);
        
        // Вывод первых 3 серверов
        result.servers.slice(0, 3).forEach((srv, i) => {
            console.log(`\n--- Сервер ${i + 1} ---`);
            console.log(parseServerUrl(srv));
        });
    } else {
        console.error('❌ Ошибка:', result.error);
    }
})();
*/
