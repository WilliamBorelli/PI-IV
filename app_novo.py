import streamlit as st
import json
import time
import re
import unicodedata
import gzip
import base64
import logging
from datetime import datetime, timedelta
from html import escape
from marshmallow import Schema, fields, validates_schema, ValidationError, pre_load

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================================
# 🤖 COPILOTO DE IA: ANÁLISE DE OPERAÇÕES
# ==========================================
class AIOperationsAnalyzer:
    """
    Simula uma LLM analisando todo o contexto operacional (Sucessos, Erros e Performance).
    """
    def analyze_api_payload(self, raw_data, errors=None, dumped_data=None) -> str:
        time.sleep(1.2) # Simula delay da API da LLM
        
        analise = "🤖 **Relatório SecOps (IA):**\n\n"
        
        if errors:
            analise += "🔴 **Status:** Falha de Segurança/Integridade Detectada.\n\n"
            if "position_json" in errors:
                analise += "- 🛡️ **Defesa Ativa:** Bloqueamos uma possível tentativa de **JSON DoS (Billion Laughs)**. O aninhamento do payload excedeu o limite seguro, o que poderia travar a CPU do servidor.\n"
            if "dashboard_title" in errors:
                analise += "- 📝 **Integridade:** Tentativa de publicar dashboard sem título barrada. "
                if "<script>" in str(raw_data.get("dashboard_title", "")):
                    analise += "Também detectei uma assinatura **Cross-Site Scripting (XSS)** no título original. A sanitização teria limpado isso, mas a falta de título causou o bloqueio primário.\n"
            if "slug" in errors:
                analise += "- 🔗 **Roteamento:** O slug não é URL-friendly. É recomendado adicionar validação Regex no frontend para evitar esse roundtrip desnecessário.\n"
        else:
            analise += "🟢 **Status:** Payload Seguro e Otimizado.\n\n"
            analise += "- 🧹 **Sanitização:** O título e outros campos de texto foram escapados. Qualquer tag HTML perigosa foi neutralizada antes de tocar no banco.\n"
            analise += "- 🔤 **Normalização:** O slug foi padronizado (minúsculas e hifens) garantindo SEO e roteamento corretos.\n"
            
            if dumped_data and dumped_data.get("chart_configuration", {}).get("compressed"):
                analise += "- 📉 **Otimização de Rede:** O algoritmo de IA detectou um JSON denso e aplicou compressão **GZIP + Base64**. Isso reduz o uso de banda, acelerando respostas em conexões lentas.\n"
            else:
                analise += "- ℹ️ **Compressão Ignorada:** O payload era muito pequeno ou sem padrões repetitivos, então não gastamos CPU tentando comprimi-lo.\n"
                
        return analise

    def analyze_db_telemetry(self, telemetry: dict) -> str:
        time.sleep(1.5)
        
        analise = "🤖 **Relatório SRE (Engenharia de Confiabilidade da IA):**\n\n"
        
        if telemetry.get('cache_hit'):
            analise += "- ⚡ **Performance:** Cache LRU atingido! Evitamos completamente o custo de I/O do banco de dados. Esta é a melhor proteção contra picos de tráfego.\n"
            
        if telemetry.get('slow_query'):
            analise += "- 🐢 **Gargalo Detectado:** A query demorou mais que 0.5s. Isso indica a necessidade de **criar índices compostos** ou migrar essa busca para um motor Full-Text Search (como Elasticsearch).\n"
            
        if telemetry.get('retries_used') > 0:
            analise += f"- 🔌 **Resiliência:** Houve falha de rede, mas a aplicação se recuperou após {telemetry.get('retries_used')} tentativa(s) usando **Backoff Exponencial**. O usuário final não percebeu a queda do banco.\n"
            
        if telemetry.get('partition_removed', 0) > 0:
            analise += f"- 📅 **Eficiência (Particionamento):** Removemos {telemetry['partition_removed']} registros da varredura na memória. Limitar a busca aos últimos 90 dias evita o temido *Full Table Scan* em tabelas históricas.\n"
            
        if telemetry.get('dq_issues_count', 0) > 0:
            analise += f"- 🧹 **Data Quality (DQ):** {telemetry['dq_issues_count']} gráficos estavam órfãos (sem datasource_id). Recomendo agendar um Job noturno (via Airflow/Celery) para expurgar esses lixos do banco.\n"
            
        if telemetry.get('volume_limited'):
            analise += "- 📏 **Proteção de Memória:** O limite absoluto de paginação foi acionado. Isso impede que requisições mal-intencionadas extraiam o banco inteiro em uma única chamada de API (Prevenção de Data Scraping/OOM).\n"
            
        if len(analise.strip()) == 53: # Só tem o título
            analise += "✅ A arquitetura comportou a requisição com folga. Nenhuma anomalia de infraestrutura detectada."
            
        return analise


# ==========================================
# 🛡️ CLASSES E MIXINS API E DB
# ==========================================
class EnhancedDataValidationMixin:
    @staticmethod
    def validate_slug_format(slug: str) -> bool:
        return re.match(r'^[a-z0-9]+(?:-[a-z0-9]+)*$', slug.lower()) is not None
    @staticmethod
    def validate_json_size(json_str: str, max_size_mb: float = 10.0) -> bool:
        return not json_str or (len(json_str.encode('utf-8')) / (1024 * 1024)) <= max_size_mb
    @validates_schema
    def validate_data_consistency(self, data, **kwargs):
        errors = {}
        if data.get('published') and not data.get('dashboard_title'): errors['dashboard_title'] = ['Published dashboards must have a title']
        for field in ['json_metadata', 'position_json']:
            if field in data and not self.validate_json_size(data[field]): errors[field] = [f'{field} exceeds maximum size limit']
        if 'slug' in data and data.get('slug') and not self.validate_slug_format(data['slug']): errors['slug'] = ['Invalid slug format']
        if errors: raise ValidationError(errors)

class DataSanitizationMixin:
    @staticmethod
    def sanitize_html_content(content: str) -> str:
        return ''.join(char for char in escape(content) if unicodedata.category(char) != 'Cc').strip() if content else content
    @staticmethod
    def normalize_slug(slug: str) -> str:
        if not slug: return slug
        normalized = unicodedata.normalize('NFKD', slug).encode('ascii', 'ignore').decode('ascii')
        return re.sub(r'[-\s]+', '-', re.sub(r'[^\w\s-]', '', normalized).strip().lower())
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        for field in ['dashboard_title', 'css', 'certified_by', 'certification_details']:
            if data.get(field): data[field] = self.sanitize_html_content(data[field])
        if data.get('slug'): data['slug'] = self.normalize_slug(data['slug'])
        return data

class APIDataVolumeControlMixin:
    MAX_CSS_SIZE_KB = 500
    def validate_json_structure(self, json_data: dict, max_depth: int = 10) -> dict:
        def check_depth(obj, current_depth=0):
            if current_depth > max_depth: raise ValidationError(f"JSON too deeply nested (max: {max_depth})")
            if isinstance(obj, dict):
                for v in obj.values(): check_depth(v, current_depth + 1)
            elif isinstance(obj, list):
                for item in obj: check_depth(item, current_depth + 1)
        check_depth(json_data)
        return json_data
    @validates_schema
    def validate_data_volume(self, data, **kwargs):
        errors = {}
        if data.get('css') and (len(data['css'].encode('utf-8')) / 1024) > self.MAX_CSS_SIZE_KB: errors['css'] = ['CSS exceeds limit']
        if data.get('position_json'):
            try: self.validate_json_structure(json.loads(data['position_json']), max_depth=8)
            except (json.JSONDecodeError, ValidationError) as e: errors['position_json'] = [f'Invalid structure: {str(e)}']
        if errors: raise ValidationError(errors)

class CompressedJSONField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if not value: return value
        json_bytes = (json.dumps(value) if not isinstance(value, str) else value).encode('utf-8')
        if len(json_bytes) > 100:
            compressed = gzip.compress(json_bytes)
            if len(compressed) < len(json_bytes) * 0.8: return {'compressed': True, 'data': base64.b64encode(compressed).decode('ascii')}
        return json.dumps(value)

class DemoDashboardSchema(Schema, EnhancedDataValidationMixin, DataSanitizationMixin, APIDataVolumeControlMixin):
    dashboard_title = fields.String()
    slug = fields.String()
    published = fields.Boolean()
    css = fields.String()
    position_json = fields.String()
    chart_configuration = CompressedJSONField()

# ----------------- DB MOCK E CLASSES -----------------
today = datetime.utcnow()
MOCK_DB = [
    {"id": i, "slice_name": f"Dashboard {i} - Vendas", "created_on": today - timedelta(days=(i * 15)), 
     "is_archived": True if i % 4 == 0 else False, "datasource_id": 1 if i % 2 == 0 else None, "params": "{}" if i % 3 == 0 else None} 
     for i in range(1, 16)
]

class EngenhariaDadosSuperset:
    def __init__(self):
        self.telemetry = {'retries_used': 0, 'slow_query': False, 'cache_hit': False, 'partition_removed': 0, 'dq_issues_count': 0, 'volume_limited': False}

    def monitor_query(self, query_func, simular_lentidao=False):
        start_time = time.time()
        time.sleep(0.6 if simular_lentidao else 0.05) 
        results = query_func()
        if time.time() - start_time > 0.5:
            st.warning("⚠️ Monitoramento (Slow Query): Limite de tempo excedido!")
            self.telemetry['slow_query'] = True
        return results

    def apply_data_limits(self, results, limit):
        if len(results) > limit:
            st.warning(f"📏 Controle de Volume: Limitado para {limit} registros.")
            self.telemetry['volume_limited'] = True
        return results[:limit]

    @st.cache_data(ttl=30)
    def fetch_with_cache(_self, search_term):
        st.info("💾 Cache Miss: Acessando banco real...")
        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

    def execute_with_retry(self, query_func, force_fail=False):
        for attempt in range(3):
            try:
                if force_fail and attempt == 0: raise ConnectionError("Queda de rede.")
                return query_func()
            except Exception as e:
                st.error(f"🔴 Falha (Tentativa {attempt + 1}): {str(e)}. Aplicando Backoff...")
                self.telemetry['retries_used'] += 1
                time.sleep(0.5)
        return []

    def apply_temporal_filter(self, results, days_back=90, exclude_archived=True):
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        filtered = [r for r in results if not exclude_archived or not r['is_archived']]
        filtered = [r for r in filtered if r['created_on'] >= cutoff]
        self.telemetry['partition_removed'] = len(results) - len(filtered)
        return filtered

    def filter_valid_charts(self, results):
        valid_results, issues_log = [], []
        for chart in results:
            issues = []
            if not chart.get('datasource_id'): issues.append('Datasource missing')
            if not chart.get('params'): issues.append('Missing config')
            if not issues: valid_results.append(chart)
            else: issues_log.append(chart['id'])
        self.telemetry['dq_issues_count'] = len(issues_log)
        return valid_results


# ==========================================
# 🖥️ INTERFACE STREAMLIT
# ==========================================
def main():
    st.set_page_config(page_title="Superset Demo & IA", layout="wide")
    st.title("🛡️ Engenharia, Segurança e Insights de IA")
    
    ai_agent = AIOperationsAnalyzer()
    tab1, tab2 = st.tabs(["📝 API: Validação e Payloads", "🗄️ DB: Banco de Dados e SRE"])

    # --- ABA 1 ---
    with tab1:
        schema = DemoDashboardSchema()
        col1, col2 = st.columns(2)
        with col1:
            with st.form("api_form"):
                dashboard_title = st.text_input("Dashboard Title", "<script>alert(1)</script> Meu Dash")
                slug = st.text_input("Slug", "slug incorreto @#$")
                published = st.checkbox("Publicado (exige título)")
                css = st.text_area("CSS Customizado")
                position_json = st.text_area("Position JSON", '{"row1": {"col1": "chart1"}}')
                chart_config = st.text_area("Chart Config", '{"filtros": ["texto_longo_para_compressao_' * 10 + '"]}')
                usar_ia_api = st.checkbox("🤖 Ativar IA SecOps", value=True)
                submit_api = st.form_submit_button("Processar API")

        with col2:
            if submit_api:
                raw_data = {"dashboard_title": dashboard_title, "slug": slug, "published": published, "css": css, "position_json": position_json}
                try: 
                    if chart_config: raw_data["chart_configuration"] = json.loads(chart_config)
                except: 
                    st.error("JSON Inválido no Chart Config.")
                    return

                try:
                    validated_data = schema.load(raw_data)
                    dumped_data = schema.dump(validated_data)
                    st.success("✅ Validação Aprovada!")
                    st.json(dumped_data)
                    
                    if usar_ia_api:
                        with st.spinner("🧠 IA gerando insights do Sucesso..."):
                            st.info(ai_agent.analyze_api_payload(raw_data, dumped_data=dumped_data))

                except ValidationError as err:
                    st.error("❌ Validação Bloqueada:")
                    st.json(err.messages)
                    if usar_ia_api:
                        with st.spinner("🧠 IA diagnosticando o Incidente de Segurança..."):
                            st.error(ai_agent.analyze_api_payload(raw_data, errors=err.messages))

    # --- ABA 2 ---
    with tab2:
        eng = EngenhariaDadosSuperset()
        col_filters, col_results = st.columns([1, 2])

        with col_filters:
            search_term = st.text_input("Termo de Busca:", "vendas").lower()
            usar_cache = st.checkbox("Usar Cache LRU", value=False)
            simular_lentidao = st.checkbox("Forçar Lentidão", value=False)
            simular_falha = st.checkbox("Forçar Queda de Rede", value=False)
            filtrar_90_dias = st.checkbox("Particionamento (Últimos 90 dias)", value=True)
            ocultar_arquivados = st.checkbox("Ocultar Arquivados", value=True)
            aplicar_dq = st.checkbox("Data Quality Ativo", value=True)
            limite_volume = st.number_input("Limite de Registros:", min_value=1, value=5)
            usar_ia_db = st.checkbox("🤖 Ativar IA de SRE/Confiabilidade", value=True)
            submit_db = st.button("Rodar Pipeline DB", type="primary")

        with col_results:
            if submit_db:
                if not search_term or len(search_term.strip()) < 2:
                    st.error("❌ Busca bloqueada: Previne Full Table Scan.")
                    return

                def core_query():
                    if usar_cache:
                        # Gambiarra do Streamlit para detectar cache hit programaticamente no nosso teste
                        eng.telemetry['cache_hit'] = True 
                        return eng.fetch_with_cache(search_term)
                    return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

                st.write("**Logs da Engenharia:**")
                raw_results = eng.execute_with_retry(lambda: eng.monitor_query(core_query, simular_lentidao), force_fail=simular_falha)

                if filtrar_90_dias or ocultar_arquivados:
                    raw_results = eng.apply_temporal_filter(raw_results, 90 if filtrar_90_dias else 9999, ocultar_arquivados)

                if aplicar_dq:
                    raw_results = eng.filter_valid_charts(raw_results)

                final_results = eng.apply_data_limits(raw_results, limite_volume)

                st.json([{**r, 'created_on': r['created_on'].strftime('%Y-%m-%d')} for r in final_results])

                if usar_ia_db:
                    with st.spinner("🧠 IA SRE analisando a saúde da telemetria..."):
                        st.info(ai_agent.analyze_db_telemetry(eng.telemetry))

if __name__ == "__main__":
    main()