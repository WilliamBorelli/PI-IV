import streamlit as st
import json
import time
import re
import unicodedata
import gzip
import base64
import hashlib
import logging
from datetime import datetime, timedelta
from html import escape
from marshmallow import Schema, fields, validates_schema, ValidationError, pre_load

# Configuração de log
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================================
# 🛡️ ABA 1: CLASSES DE API E PAYLOADS
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
# 🗄️ ABA 2: CLASSES DE BANCO DE DADOS E MOCK
# ==========================================
# Mock DB expandido para suportar Particionamento e Arquivamento (Datas e Status)
today = datetime.utcnow()
MOCK_DB = [
    {
        "id": i, 
        "slice_name": f"Dashboard {i} - Vendas", 
        "description": f"Desc {i}", 
        "created_on": today - timedelta(days=(i * 15)), # Gráficos variando de hoje até 225 dias atrás
        "is_archived": True if i % 4 == 0 else False,   # 1 a cada 4 é arquivado
        "datasource_id": 1 if i % 2 == 0 else None,     # Alguns sem datasource para falhar no Data Quality
        "params": "{}" if i % 3 == 0 else None
    } for i in range(1, 16)
]

class EngenhariaDadosSuperset:
    """Classe unificada contendo as lógicas do PDF para o Streamlit"""
    
    # 1 e 4. Monitoramento e Otimização
    def monitor_query(self, query_func, simular_lentidao=False):
        start_time = time.time()
        time.sleep(0.6 if simular_lentidao else 0.05) # Simula DB
        results = query_func()
        exec_time = time.time() - start_time
        
        if exec_time > 0.5:
            st.warning(f"⚠️ Monitoramento (Slow Query): Query executada em {exec_time:.2f}s. Limite excedido!")
        else:
            st.success(f"⚡ Monitoramento: Query rápida ({exec_time:.2f}s).")
        return results

    # 2. Volume Control (Paginação)
    def apply_data_limits(self, results, limit):
        if len(results) > limit:
            st.warning(f"📏 Controle de Volume: Query retornou {len(results)} registros. Limitando para {limit} para proteger a memória.")
        return results[:limit]

    # 3. Cache
    @st.cache_data(ttl=30) # Cache do Streamlit simulando o lru_cache
    def fetch_with_cache(_self, search_term):
        st.info("💾 Cache Miss: Acessando o banco de dados real... (Na próxima busca igual, será instantâneo)")
        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

    # 5. Otimização de Conexões (Retry)
    def execute_with_retry(self, query_func, force_fail=False):
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if force_fail and attempt == 0:
                    raise ConnectionError("Simulação de queda de rede no banco.")
                return query_func()
            except Exception as e:
                st.error(f"🔴 Conexão falhou (Tentativa {attempt + 1}): {str(e)}. Aplicando Backoff...")
                time.sleep(0.5) # Simula o backoff exponencial
        return []

    # 6. Particionamento e Arquivamento
    def apply_temporal_filter(self, results, days_back=90, exclude_archived=True):
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        filtered = results
        
        if exclude_archived:
            filtered = [r for r in filtered if not r['is_archived']]
            
        return [r for r in filtered if r['created_on'] >= cutoff]

    # 7. Data Quality
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
# 🖥️ INTERFACE PRINCIPAL
# ==========================================
def main():
    st.set_page_config(page_title="Superset Data Eng Demo", layout="wide")
    st.title("🛡️ Engenharia de Dados: Superset")

    tab1, tab2 = st.tabs(["📝 API: Validação e Payloads", "🗄️ DB: Buscas, Cache e Filtros"])

    # ABA 1 (Mantida Oculta para brevidade, insira o código da aba 1 aqui)
    with tab1:
        st.write("Aba de APIs (Funcionalidades da resposta anterior operando normalmente).")

    # ABA 2 (Focada nos 7 tópicos do PDF)
    with tab2:
        st.header("Pipeline de Consultas do Banco de Dados")
        st.markdown("Testando os 7 conceitos de Engenharia de Dados descritos no documento.")

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
            
            btn_search = st.button("Executar Pipeline SQL", type="primary")

        with col_results:
            if btn_search:
                # Tópico 1: Otimização (Evitar busca ampla)
                if not search_term or len(search_term.strip()) < 2:
                    st.error("❌ Tópico 1: Busca bloqueada. Termo muito curto exige full table scan no banco.")
                    return

                # Montagem da Query Fictícia
                def core_query():
                    if usar_cache:
                        return eng.fetch_with_cache(search_term)
                    else:
                        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

                st.subheader("Logs do Pipeline de Engenharia")
                
                # Tópico 5: Retry + Tópico 4: Monitoramento
                raw_results = eng.execute_with_retry(
                    lambda: eng.monitor_query(core_query, simular_lentidao),
                    force_fail=simular_falha
                )

                # Tópico 6: Particionamento e Arquivamento
                if filtrar_90_dias or ocultar_arquivados:
                    pre_len = len(raw_results)
                    raw_results = eng.apply_temporal_filter(
                        raw_results, 
                        days_back=90 if filtrar_90_dias else 9999,
                        exclude_archived=ocultar_arquivados
                    )
                    st.info(f"📅 Particionamento/Arquivamento: {pre_len - len(raw_results)} registros antigos ou arquivados foram removidos.")

                # Tópico 7: Data Quality
                if aplicar_dq:
                    raw_results, issues = eng.filter_valid_charts(raw_results)
                    if issues:
                        st.info(f"🧹 Data Quality: {len(issues)} charts corrompidos removidos.")
                        with st.expander("Ver logs de corrupção de dados"): st.json(issues)

                # Tópico 2: Volume Control
                final_results = eng.apply_data_limits(raw_results, limite_volume)

                st.subheader(f"Resultado Final ({len(final_results)} registros)")
                # Formatando datas para visualização no JSON
                for r in final_results: r['created_on'] = r['created_on'].strftime('%Y-%m-%d')
                st.json(final_results)

if __name__ == "__main__":
    main()