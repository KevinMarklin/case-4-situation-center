hide_streamlit_style = """
<style>
    /* Скрываем лишние элементы интерфейса Streamlit */
    header {visibility: hidden !important;}
    #MainMenu {visibility: hidden !important;}
    footer {visibility: hidden !important;}
    [data-testid="stStatusWidget"] {visibility: hidden !important; display: none !important;}
    .stApp > header {display: none !important;}

    /* Универсальный стиль для всех датафреймов в Streamlit */
    [data-testid="stDataFrame"], [data-testid="stTable"] {
        border: 1px solid #30363D !important;
        border-radius: 12px !important;
        overflow: hidden !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4) !important;
    }
</style>
"""
METRIC_CARD_CSS = """
<style>
    /* Стили для контейнера метрики Streamlit */
    [data-testid="stMetric"] {
        background-color: #161B22;
        border: 1px solid #30363D;
        padding: 15px 20px;
        border-radius: 12px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        transition: all 0.3s ease;
    }
    
    /* Эффект при наведении мыши на карточку */
    [data-testid="stMetric"]:hover {
        border-color: #58A6FF;
        box-shadow: 0 6px 16px rgba(88, 166, 255, 0.15);
    }

    /* Настройка цвета и размера заголовка метрики */
    [data-testid="stMetricLabel"] {
        font-size: 14px !important;
        color: #8B949E !important;
    }

    /* Настройка цвета и размера самого числа */
    [data-testid="stMetricValue"] {
        font-size: 28px !important;
        font-weight: 700 !important;
        color: #C9D1D9 !important;
    }
</style>
"""

BUTTON_AND_RESULT_CSS = """
<style>
    /* Кастомизация кнопки Streamlit (st.button) */
    [data-testid="stButton"] button {
        background-color: #21262D !important;
        color: #58A6FF !important;
        border: 1px solid #30363D !important;
        border-radius: 10px !important;
        padding: 0.5rem 1rem !important;
        font-weight: 600 !important;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2) !important;
        transition: all 0.3s ease !important;
    }
    
    /* Эффект при наведении мыши на кнопку */
    [data-testid="stButton"] button:hover {
        background-color: #30363D !important;
        border-color: #58A6FF !important;
        color: #79C0FF !important;
        box-shadow: 0 6px 14px rgba(88, 166, 255, 0.25) !important;
    }

    /* Стили для блоков вывода результатов (st.success, st.info, st.container) */
    [data-testid="stSuccess"] {
        background-color: rgba(63, 185, 80, 0.1) !important;
        border: 1px solid rgba(63, 185, 80, 0.4) !important;
        border-radius: 12px !important;
        color: #3FB950 !important;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }
    
    [data-testid="stInfo"] {
        background-color: rgba(88, 166, 255, 0.1) !important;
        border: 1px solid rgba(88, 166, 255, 0.4) !important;
        border-radius: 12px !important;
        color: #58A6FF !important;
    }
</style>
"""
# функция для цвета
def color_severity(val):
        if  "CRITICAL" in str(val).upper():
            return 'background-color: rgba(248, 81, 73, 0.2); color: #ff7b72; font-weight: bold;'
        elif "WARNING" in str(val).upper():
            return 'background-color: rgba(227, 179, 65, 0.2); color: #d29922; font-weight: bold;'
        elif "STALE" in str(val).upper():
            return 'background-color: rgba(232, 62, 140, 0.2); color: #f06595; font-weight: bold;'    
        return ""

def color_sever(val):
     if "ALERT_CREATED" in str(val).upper():
          return 'color: #3FB950'
     if "ESCALATED" in str(val).upper():
          return 'color: #d29922'

#делает текст жирным
def make_bold(val):
     return 'font-weight: bold;'


#лавандовый цвет
def make_lavand(val):
     return 'color: #BC8CFF;'
