import json
import joblib
import ipaddress
import re
import os
from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlsplit, unquote

# Инициализация Flask (Vercel ищет переменную "app")
app = Flask(__name__)

# Загрузка модели
print("Загружаем модель PhishEye...")
model_path = os.path.join(os.path.dirname(__file__), "phisheye_hybrid_model_hardnegatives.pkl")
model = joblib.load(model_path)
PHISHING_THRESHOLD = 0.80
print("Модель загружена.")

def analyze_url(url):
    """Анализирует структуру URL и объясняет найденные особенности."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = unquote(parts.path).lower()
    query = unquote(parts.query).lower()
    findings = []

    def add_finding(title, description, location, level="warning"):
        findings.append({
            "title": title,
            "description": description,
            "location": location,
            "level": level
        })

    if parts.scheme.lower() == "http":
        add_finding("Нет защищённого HTTPS-соединения", "Соединение использует HTTP без HTTPS-шифрования. Это не доказывает фишинг, но требует внимания.", "Протокол", "warning")

    try:
        ipaddress.ip_address(host)
        add_finding("Вместо домена используется IP-адрес", "Адрес ведёт непосредственно на IP. Такой способ использования не доказывает фишинг, но требует внимания.", "Домен", "danger")
    except ValueError:
        pass

    if "xn--" in host:
        add_finding("Обнаружен Punycode", "Домен содержит кодированные символы. Иногда это используется для создания адресов, похожих на известные домены.", "Домен", "danger")

    labels = host.split(".") if host else []
    if len(labels) >= 4:
        add_finding("Много уровней домена", f"В адресе обнаружено {len(labels)} частей доменного имени. Длинная цепочка поддоменов может затруднять определение основного домена.", "Домен", "warning")

    word_categories = {
        "авторизация": ["login", "signin", "authenticate", "password"],
        "подтверждение данных": ["verify", "confirm", "account", "update"],
        "финансовые операции": ["wallet", "banking"]
    }
    locations = {"домен": host, "путь": path, "параметры": query}
    found_words = []
    found_locations = []

    for category, words in word_categories.items():
        for word in words:
            pattern = r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])"
            for location, value in locations.items():
                if re.search(pattern, value):
                    found_words.append(word)
                    if location not in found_locations:
                        found_locations.append(location)
                    break

    if found_words:
        found_words = list(dict.fromkeys(found_words))
        add_finding("Обнаружены слова, связанные с действиями пользователя", "Найдены элементы: " + ", ".join(found_words) + ". Они могут встречаться как на фишинговых, так и на обычных сайтах, поэтому сами по себе не подтверждают угрозу.", ", ".join(found_locations), "warning")

    if "@" in parts.netloc:
        add_finding("Символ @ в адресе", "Часть адреса перед символом @ может выглядеть как домен, хотя фактический адресат находится после него.", "Адрес сервера", "danger")

    if len(url) > 100:
        add_finding("Большая длина ссылки", f"URL содержит {len(url)} символов. Длинные адреса сложнее проверять визуально.", "Весь URL", "info")

    digit_count = sum(char.isdigit() for char in host)
    if digit_count >= 5:
        add_finding("Много цифр в доменном имени", f"В домене обнаружено {digit_count} цифр. Это может быть особенностью адреса или способом маскировки похожего написания.", "Домен", "warning")

    try:
        port = parts.port
        if port is not None and port not in (80, 443):
            add_finding("Используется нестандартный порт", f"В адресе указан порт {port}. Это не обязательно опасно, но для обычных веб-сайтов чаще используются порты 80 и 443.", "Адрес сервера", "warning")
    except ValueError:
        pass

    if re.search(r"%[0-9a-fA-F]{2}", url):
        add_finding("В адресе есть кодированные символы", "Часть URL записана в кодированном виде. Это стандартный механизм веб-адресов, но иногда он затрудняет визуальную проверку.", "Путь или параметры", "info")

    suspicious_extensions = [".exe", ".scr", ".bat", ".cmd", ".msi", ".apk"]
    found_extensions = [ext for ext in suspicious_extensions if path.endswith(ext)]
    if found_extensions:
        add_finding("Подозрительное расширение файла", "Путь заканчивается на " + ", ".join(found_extensions) + ". Такие расширения могут использоваться для распространения исполняемых файлов.", "Путь", "danger")

    if not findings:
        add_finding("Явные структурные признаки не найдены", "Простые проверки не выявили перечисленных особенностей. Это не подтверждает безопасность сайта.", "Весь URL", "info")

    return findings

# Раздача главной страницы (вашего index.html)
@app.route('/')
def home():
    return send_from_directory('.', 'index.html')

# Эндпоинт для предсказания
@app.route('/predict', methods=['POST'])
def predict():
    try:
        body = request.get_json()
        if not isinstance(body, dict):
            return jsonify({"error": "Некорректный формат запроса"}), 400

        url = body.get("url", "")
        if not isinstance(url, str):
            return jsonify({"error": "Ссылка должна быть текстом"}), 400

        url = url.strip()
        if not url:
            return jsonify({"error": "Введите ссылку"}), 400

        parts = urlsplit(url)
        if (parts.scheme not in ("http", "https") or not parts.hostname or
            any(char.isspace() for char in url) or
            parts.username is not None or parts.password is not None):
            return jsonify({"error": "Некорректная HTTP(S)-ссылка"}), 400

        probabilities = model.predict_proba([url])[0]
        classes = list(model.classes_)
        phishing_probability = float(probabilities[classes.index(0)])

        host = (parts.hostname or "").lower()
        is_known_google_drive = host == "drive.google.com"

        if is_known_google_drive:
            prediction = 1
            status = "not_detected"
            message = "Используется официальный домен Google Drive. Модель оценила ссылку как подозрительную, но для этого домена результат не считается фишингом."
        elif phishing_probability >= PHISHING_THRESHOLD:
            prediction = 0
            status = "suspicious"
            message = "Модель обнаружила признаки фишинга."
        else:
            prediction = 1
            status = "not_detected"
            message = "Модель не обнаружила выраженных признаков фишинга."

        findings = analyze_url(url)

        return jsonify({
            "status": status,
            "url": url,
            "prediction": prediction,
            "phishing_probability": round(phishing_probability * 100, 2),
            "message": message,
            "findings": findings,
            "warning": "Оценка модели и структурные признаки не являются гарантией безопасности ссылки."
        })

    except Exception as error:
        print("Ошибка анализа:", error)
        return jsonify({"error": "Не удалось выполнить анализ ссылки."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
