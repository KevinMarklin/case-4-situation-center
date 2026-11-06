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
