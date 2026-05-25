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
# 🤖 NOVA CAMADA: ANÁLISE POR IA (LLM)
# ==========================================
class AIPayloadAnalyzer:
    """
    Simula a integração com uma LLM (Gemini, OpenAI, Claude) 
    para analisar payloads e explicar falhas de segurança/validação.
    """
    def analyze_api_error(self, raw_payload: dict, error_messages: dict) -> str:
        """Envia o payload e o erro para a IA explicar."""
        # Na vida real, aqui entraria o código: 
        # response = openai.ChatCompletion.create(prompt=f"Explique este erro: {error_messages} no payload {raw_payload}")
        
        time.sleep(1.5) # Simula o delay da rede da LLM
        
        # Gerando respostas dinâmicas baseadas no tipo de erro simulado
        analise = "**Análise da IA de Segurança:**\n\n"
        
        if "position_json" in error_messages:
            analise += "🕵️‍♂️ **Detecção de Anomalia:** Notei que o campo `position_json` contém um nível de aninhamento extremamente profundo. Isso é uma assinatura clássica de um ataque **Billion Laughs** ou **JSON DoS** (Denial of Service), onde o atacante tenta esgotar a memória do nosso parser.\n\n"
            analise += "* **Recomendação:** Mantenha o bloqueio do `APIDataVolumeControlMixin` e considere bloquear temporariamente o IP de origem."
            
        elif "dashboard_title" in error_messages:
            analise += "📝 **Regra de Negócio Violada:** O usuário tentou publicar um dashboard sem título. \n\n"
            analise += "* **Impacto UX:** Dashboards sem título quebram a renderização do catálogo frontal.\n"
            if "<script>" in str(raw_payload.get("dashboard_title", "")):
                analise += "⚠️ **ALERTA CRÍTICO:** Além disso, o título original continha tags HTML perigosas indicando uma tentativa de **Cross-Site Scripting (XSS)**. A camada de sanitização agiu corretamente antes do bloqueio."
        
        elif "slug" in error_messages:
            analise += "🔗 **Formatação de Rota:** O slug fornecido não segue o padrão URL-friendly esperado (apenas letras minúsculas, números e hifens).\n"
            analise += "* **Correção sugerida:** O frontend deve forçar a validação usando o Regex `^[a-z0-9]+(?:-[a-z0-9]+)*$` antes de enviar o payload."
        else:
            analise += "🔍 Analisei os erros reportados e eles estão consistentes com as regras de integridade de dados."

        return analise

    def analyze_data_quality(self, issues: list) -> str:
        """Analisa os problemas de corrupção do banco de dados."""
        time.sleep(1.5)
        total = len(issues)
        analise = f"**Relatório do Agente de IA (Data Quality):**\n\n"
        analise += f"Analisei os {total} gráficos corrompidos barrados pelo filtro.\n"
        analise += "- 📉 A maioria apresenta falha no `datasource_id`, o que sugere que um banco de dados foi deletado, mas os gráficos continuaram órfãos no sistema.\n"
        analise += "- 🛠️ **Ação Recomendada:** Sugiro rodar um script de limpeza (Garbage Collection) no banco de dados para remover metadados órfãos e melhorar a performance geral das queries."
        return analise


# ==========================================
# 🛡️ PARTE 1: SEGURANÇA E VALIDAÇÃO DE APIs
# ==========================================
class EnhancedDataValidationMixin:
    @staticmethod
    def validate_slug_format(slug: str) -> bool:
        pattern = r'^[a-z0-9]+(?:-[a-z0-9]+)*$'
        return re.match(pattern, slug.lower()) is not None
    
    @staticmethod
    def validate_json_size(json_str: str, max_size_mb: float = 10.0) -> bool:
        if not json_str: return True
        return (len(json_str.encode('utf-8')) / (1024 * 1024)) <= max_size_mb
    
    @validates_schema
    def validate_data_consistency(self, data, **kwargs):
        errors = {}
        if data.get('published') and not data.get('dashboard_title'):
            errors['dashboard_title'] = ['Published dashboards must have a title']
        for field in ['json_metadata', 'position_json']:
            if field in data and not self.validate_json_size(data[field]):
                errors[field] = [f'{field} exceeds maximum size limit']
        if 'slug' in data and data['slug']:
            if not self.validate_slug_format(data['slug']):
                errors['slug'] = ['Invalid slug format']
        if errors: raise ValidationError(errors)

class DataSanitizationMixin:
    @staticmethod
    def sanitize_html_content(content: str) -> str:
        if not content: return content
        sanitized = ''.join(char for char in escape(content) if unicodedata.category(char) != 'Cc')
        return sanitized.strip()
    
    @staticmethod
    def normalize_slug(slug: str) -> str:
        if not slug: return slug
        normalized = unicodedata.normalize('NFKD', slug).encode('ascii', 'ignore').decode('ascii')
        normalized = re.sub(r'[^\w\s-]', '', normalized).strip().lower()
        return re.sub(r'[-\s]+', '-', normalized)
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        for field in ['dashboard_title', 'css', 'certified_by', 'certification_details']:
            if field in data and data[field]: 
                data[field] = self.sanitize_html_content(data[field])
        if 'slug' in data and data['slug']: 
            data['slug'] = self.normalize_slug(data['slug'])
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
        if data.get('css') and (len(data['css'].encode('utf-8')) / 1024) > self.MAX_CSS_SIZE_KB:
            errors['css'] = [f'CSS exceeds {self.MAX_CSS_SIZE_KB}KB limit']
        if data.get('position_json'):
            try:
                self.validate_json_structure(json.loads(data['position_json']), max_depth=8)
            except (json.JSONDecodeError, ValidationError) as e:
                errors['position_json'] = [f'Invalid structure: {str(e)}']
        if errors: raise ValidationError(errors)

class CompressedJSONField(fields.Field):
    def _serialize(self, value, attr, obj, **kwargs):
        if not value: return value
        json_bytes = (json.dumps(value) if not isinstance(value, str) else value).encode('utf-8')
        if len(json_bytes) > 100:
            compressed = gzip.compress(json_bytes)
            if len(compressed) < len(json_bytes) * 0.8: 
                return {'compressed': True, 'data': base64.b64encode(compressed).decode('ascii')}
        return json.dumps(value)

class DemoDashboardSchema(Schema, EnhancedDataValidationMixin, DataSanitizationMixin, APIDataVolumeControlMixin):
    dashboard_title = fields.String()
    slug = fields.String()
    published = fields.Boolean()
    css = fields.String()
    position_json = fields.String()
    chart_configuration = CompressedJSONField()


# ==========================================
# 🗄️ PARTE 2: ENGENHARIA E PERFORMANCE DE DB
# ==========================================
today = datetime.utcnow()
MOCK_DB = [
    {
        "id": i, 
        "slice_name": f"Dashboard {i} - Vendas", 
        "description": f"Desc {i}", 
        "created_on": today - timedelta(days=(i * 15)), 
        "is_archived": True if i % 4 == 0 else False,   
        "datasource_id": 1 if i % 2 == 0 else None,     
        "params": "{}" if i % 3 == 0 else None
    } for i in range(1, 16)
]

class EngenhariaDadosSuperset:
    def monitor_query(self, query_func, simular_lentidao=False):
        start_time = time.time()
        time.sleep(0.6 if simular_lentidao else 0.05) 
        results = query_func()
        exec_time = time.time() - start_time
        
        if exec_time > 0.5:
            st.warning(f"⚠️ Monitoramento (Slow Query): Query executada em {exec_time:.2f}s. Limite excedido!")
        else:
            st.success(f"⚡ Monitoramento: Query rápida ({exec_time:.2f}s).")
        return results

    def apply_data_limits(self, results, limit):
        if len(results) > limit:
            st.warning(f"📏 Controle de Volume: Query retornou {len(results)} registros. Limitando para {limit} para proteger a memória.")
        return results[:limit]

    @st.cache_data(ttl=30)
    def fetch_with_cache(_self, search_term):
        st.info("💾 Cache Miss: Acessando o banco de dados real... (Na próxima busca igual, será instantâneo)")
        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

    def execute_with_retry(self, query_func, force_fail=False):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if force_fail and attempt == 0:
                    raise ConnectionError("Simulação de queda de rede no banco.")
                return query_func()
            except Exception as e:
                st.error(f"🔴 Conexão falhou (Tentativa {attempt + 1}): {str(e)}. Aplicando Backoff...")
                time.sleep(0.5)
        return []

    def apply_temporal_filter(self, results, days_back=90, exclude_archived=True):
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        filtered = results
        if exclude_archived:
            filtered = [r for r in filtered if not r['is_archived']]
        return [r for r in filtered if r['created_on'] >= cutoff]

    def filter_valid_charts(self, results):
        valid_results, issues_log = [], []
        for chart in results:
            issues = []
            if not chart.get('datasource_id'): issues.append('Datasource missing')
            if not chart.get('params'): issues.append('Missing configuration')
            if not issues: valid_results.append(chart)
            else: issues_log.append({"id": chart['id'], "issues": issues})
        return valid_results, issues_log


# ==========================================
# 🖥️ PARTE 3: INTERFACE VISUAL (STREAMLIT)
# ==========================================
def main():
    st.set_page_config(page_title="Superset Complete Demo", layout="wide")
    st.title("🛡️ Engenharia de Dados, Segurança e IA: Apache Superset")
    
    # Instanciando o nosso agente de IA
    ai_agent = AIPayloadAnalyzer()

    tab1, tab2 = st.tabs(["📝 API: Validação e Payloads", "🗄️ DB: Buscas, Cache e Filtros"])

    # ------------------------------------------
    # ABA 1: FRONTEND DAS APIS
    # ------------------------------------------
    with tab1:
        st.header("Entrada e Sanitização de Dados (Payloads)")
        schema = DemoDashboardSchema()
        col1, col2 = st.columns(2)

        with col1:
            with st.form("demo_form"):
                dashboard_title = st.text_input("Dashboard Title (Tente usar tags HTML <script>alert(1)</script>)")
                slug = st.text_input("Slug (Tente usar espaços ou caracteres especiais)")
                published = st.checkbox("Publicado (Se marcado, exige título)")
                css = st.text_area("CSS Customizado")
                position_json = st.text_area("Position JSON (Aninhamento > 8 simula erro)", '{"row1": {"col1": "chart1"}}')
                chart_config = st.text_area("Chart Configuration JSON (Texto longo testa a compressão)", '{"filtros": ["long_string_to_force_compression_threshold_' * 10 + '"]}')
                
                # Nova flag de IA
                st.divider()
                usar_ia_api = st.checkbox("🤖 Ativar Análise de IA para Erros de Payload", value=True)
                
                submit = st.form_submit_button("Processar Dados")

        with col2:
            if submit:
                raw_data = {"dashboard_title": dashboard_title, "slug": slug, "published": published, "css": css, "position_json": position_json}
                try:
                    if chart_config: raw_data["chart_configuration"] = json.loads(chart_config)
                except json.JSONDecodeError:
                    st.error("❌ Erro: O Chart Configuration não é um JSON válido.")
                    return

                try:
                    validated_data = schema.load(raw_data)
                    st.success("✅ Validação passou com sucesso!")
                    st.write("**Dados Sanitizados:**")
                    st.json({"dashboard_title": validated_data.get("dashboard_title"), "slug": validated_data.get("slug")})

                    dumped_data = schema.dump(validated_data)
                    st.write("**Payload Final (Compressão):**")
                    st.json(dumped_data)

                except ValidationError as err:
                    st.error("❌ Falha na Validação (Bloqueado pelas Regras):")
                    st.json(err.messages)
                    
                    # INTEGRAÇÃO DA IA AQUI
                    if usar_ia_api:
                        with st.spinner("🧠 IA analisando o incidente de segurança..."):
                            analise = ai_agent.analyze_api_error(raw_data, err.messages)
                        st.info(analise)

    # ------------------------------------------
    # ABA 2: FRONTEND DO BANCO DE DADOS
    # ------------------------------------------
    with tab2:
        st.header("Motor de Busca e Gestão de Banco de Dados")

        eng = EngenhariaDadosSuperset()
        col_filters, col_results = st.columns([1, 2])

        with col_filters:
            st.subheader("Parâmetros de Busca")
            search_term = st.text_input("1. Termo de Busca (Mín 2 chars):", "vendas").lower()
            
            st.divider()
            st.markdown("**Simulações de Infraestrutura**")
            usar_cache = st.checkbox("3. Usar Cache de Dados (LRU)", value=False)
            simular_lentidao = st.checkbox("4. Forçar Lentidão (Testar Monitoramento)", value=False)
            simular_falha = st.checkbox("5. Forçar Falha de Conexão (Testar Retry)", value=False)
            
            st.divider()
            st.markdown("**Filtros e Engenharia**")
            filtrar_90_dias = st.checkbox("6. Particionamento: Apenas últimos 90 dias", value=False)
            ocultar_arquivados = st.checkbox("6. Arquivamento: Ocultar Arquivados", value=False)
            aplicar_dq = st.checkbox("7. Data Quality: Ocultar dados corrompidos", value=False)
            limite_volume = st.number_input("2. Controle de Volume (Max Resultados):", min_value=1, max_value=20, value=5)
            
            # Nova flag de IA
            st.divider()
            usar_ia_db = st.checkbox("🤖 Ativar IA para Insights de Data Quality", value=True)
            
            btn_search = st.button("Executar Pipeline SQL", type="primary")

        with col_results:
            if btn_search:
                if not search_term or len(search_term.strip()) < 2:
                    st.error("❌ Tópico 1: Busca bloqueada. Termo muito curto exige full table scan no banco.")
                    return

                def core_query():
                    if usar_cache:
                        return eng.fetch_with_cache(search_term)
                    else:
                        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

                st.subheader("Logs do Pipeline de Engenharia")
                
                raw_results = eng.execute_with_retry(
                    lambda: eng.monitor_query(core_query, simular_lentidao),
                    force_fail=simular_falha
                )

                if filtrar_90_dias or ocultar_arquivados:
                    pre_len = len(raw_results)
                    raw_results = eng.apply_temporal_filter(
                        raw_results, 
                        days_back=90 if filtrar_90_dias else 9999,
                        exclude_archived=ocultar_arquivados
                    )
                    st.info(f"📅 Particionamento/Arquivamento: {pre_len - len(raw_results)} registros antigos ou arquivados foram removidos.")

                if aplicar_dq:
                    raw_results, issues = eng.filter_valid_charts(raw_results)
                    if issues:
                        st.info(f"🧹 Data Quality: {len(issues)} charts corrompidos removidos pela regra estrita.")
                        with st.expander("Ver logs brutos de corrupção de dados"): 
                            st.json(issues)
                        
                        # INTEGRAÇÃO DA IA AQUI
                        if usar_ia_db:
                            with st.spinner("🧠 IA gerando insights sobre a saúde do banco de dados..."):
                                insights = ai_agent.analyze_data_quality(issues)
                            st.info(insights)

                final_results = eng.apply_data_limits(raw_results, limite_volume)

                st.subheader(f"Resultado Final ({len(final_results)} registros)")
                
                display_results = []
                for r in final_results:
                    item = r.copy()
                    if isinstance(item['created_on'], datetime):
                        item['created_on'] = item['created_on'].strftime('%Y-%m-%d')
                    display_results.append(item)
                    
                st.json(display_results)

if __name__ == "__main__":
    main()