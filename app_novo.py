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

# Configuração de log para monitoramento
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================================
# 🛡️ PARTE 1: SEGURANÇA E VALIDAÇÃO DE APIs
# ==========================================

class EnhancedDataValidationMixin:
    """
    Mixin focado em Regras de Negócio e Proteção contra Entradas Maliciosas.
    Garante que os dados façam sentido antes de chegarem ao banco.
    """
    @staticmethod
    def validate_slug_format(slug: str) -> bool:
        # Previne URLs inválidas ou injeção de caracteres de controle em rotas
        pattern = r'^[a-z0-9]+(?:-[a-z0-9]+)*$'
        return re.match(pattern, slug.lower()) is not None
    
    @staticmethod
    def validate_json_size(json_str: str, max_size_mb: float = 10.0) -> bool:
        # Previne estouro de memória limitando o tamanho físico do payload em MB
        if not json_str: return True
        return (len(json_str.encode('utf-8')) / (1024 * 1024)) <= max_size_mb
    
    @validates_schema
    def validate_data_consistency(self, data, **kwargs):
        """Validação cruzada: verifica dependências entre campos diferentes"""
        errors = {}
        
        # Regra de Negócio: Um dashboard não pode ser publicado sem título
        if data.get('published') and not data.get('dashboard_title'):
            errors['dashboard_title'] = ['Published dashboards must have a title']
            
        # Proteção de Memória: Valida o tamanho dos campos JSON
        for field in ['json_metadata', 'position_json']:
            if field in data and not self.validate_json_size(data[field]):
                errors[field] = [f'{field} exceeds maximum size limit']
                
        # Consistência de URL
        if 'slug' in data and data['slug']:
            if not self.validate_slug_format(data['slug']):
                errors['slug'] = ['Invalid slug format']
                
        if errors: raise ValidationError(errors)

class DataSanitizationMixin:
    """
    Mixin focado em Limpeza de Dados.
    Roda ANTES da validação (@pre_load) para neutralizar ameaças (ex: XSS).
    """
    @staticmethod
    def sanitize_html_content(content: str) -> str:
        # Escapa tags HTML perigosas (ex: <script>) e remove caracteres de controle invisíveis
        if not content: return content
        sanitized = ''.join(char for char in escape(content) if unicodedata.category(char) != 'Cc')
        return sanitized.strip()
    
    @staticmethod
    def normalize_slug(slug: str) -> str:
        # Remove acentos, transforma espaços em hifens e força letras minúsculas
        if not slug: return slug
        normalized = unicodedata.normalize('NFKD', slug).encode('ascii', 'ignore').decode('ascii')
        normalized = re.sub(r'[^\w\s-]', '', normalized).strip().lower()
        return re.sub(r'[-\s]+', '-', normalized)
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        """Aplica a limpeza automaticamente em todos os campos de texto"""
        for field in ['dashboard_title', 'css', 'certified_by', 'certification_details']:
            if field in data and data[field]: 
                data[field] = self.sanitize_html_content(data[field])
        if 'slug' in data and data['slug']: 
            data['slug'] = self.normalize_slug(data['slug'])
        return data

class APIDataVolumeControlMixin:
    """
    Mixin focado em Prevenção de Ataques de Negação de Serviço (DoS).
    """
    MAX_CSS_SIZE_KB = 500
    
    def validate_json_structure(self, json_data: dict, max_depth: int = 10) -> dict:
        """
        Analisa a profundidade do JSON. JSONs infinitamente aninhados 
        podem travar o parser do servidor (Billion Laughs / JSON DoS).
        """
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
        # Limita o tamanho do CSS malicioso
        if data.get('css') and (len(data['css'].encode('utf-8')) / 1024) > self.MAX_CSS_SIZE_KB:
            errors['css'] = [f'CSS exceeds {self.MAX_CSS_SIZE_KB}KB limit']
            
        # Valida a estrutura profunda do JSON de posições
        if data.get('position_json'):
            try:
                self.validate_json_structure(json.loads(data['position_json']), max_depth=8)
            except (json.JSONDecodeError, ValidationError) as e:
                errors['position_json'] = [f'Invalid structure: {str(e)}']
        if errors: raise ValidationError(errors)

class CompressedJSONField(fields.Field):
    """
    Otimização de Rede: Comprime payloads grandes antes de salvar/enviar,
    reduzindo custos de transferência e latência.
    """
    def _serialize(self, value, attr, obj, **kwargs):
        if not value: return value
        json_bytes = (json.dumps(value) if not isinstance(value, str) else value).encode('utf-8')
        
        # Só comprime se valer a pena (tamanho > 100 bytes e redução > 20%)
        if len(json_bytes) > 100:
            compressed = gzip.compress(json_bytes)
            if len(compressed) < len(json_bytes) * 0.8: 
                return {'compressed': True, 'data': base64.b64encode(compressed).decode('ascii')}
        return json.dumps(value)

# Schema final aglomerando todas as proteções
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

# Banco de Dados Simulado (Mock) com dados propositalmente sujos/antigos
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
    """Implementação dos 7 tópicos de performance do PDF"""
    
    # Tópico 4: Monitoramento e Métricas
    def monitor_query(self, query_func, simular_lentidao=False):
        """Mede o tempo da query e gera alertas de observabilidade se exceder o limite (0.5s)"""
        start_time = time.time()
        time.sleep(0.6 if simular_lentidao else 0.05) 
        results = query_func()
        exec_time = time.time() - start_time
        
        if exec_time > 0.5:
            st.warning(f"⚠️ Monitoramento (Slow Query): Query executada em {exec_time:.2f}s. Limite excedido!")
        else:
            st.success(f"⚡ Monitoramento: Query rápida ({exec_time:.2f}s).")
        return results

    # Tópico 2: Paginação e Volume Control
    def apply_data_limits(self, results, limit):
        """Aplica um hard-limit nos resultados para evitar Out-Of-Memory no servidor"""
        if len(results) > limit:
            st.warning(f"📏 Controle de Volume: Query retornou {len(results)} registros. Limitando para {limit} para proteger a memória.")
        return results[:limit]

    # Tópico 3: Cache Inteligente
    @st.cache_data(ttl=30)
    def fetch_with_cache(_self, search_term):
        """Simula um lru_cache. Impede que o banco de dados processe buscas repetidas."""
        st.info("💾 Cache Miss: Acessando o banco de dados real... (Na próxima busca igual, será instantâneo)")
        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

    # Tópico 5: Conexões de Banco
    def execute_with_retry(self, query_func, force_fail=False):
        """Garante resiliência (Backoff Exponencial) caso o banco sofra microquedas."""
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

    # Tópico 6: Particionamento e Arquivamento
    def apply_temporal_filter(self, results, days_back=90, exclude_archived=True):
        """Acelera queries limitando a busca apenas a partições de datas recentes/ativas."""
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        filtered = results
        if exclude_archived:
            filtered = [r for r in filtered if not r['is_archived']]
        return [r for r in filtered if r['created_on'] >= cutoff]

    # Tópico 7: Data Quality
    def filter_valid_charts(self, results):
        """Garante a integridade: impede que a interface quebre ao tentar renderizar charts corrompidos."""
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
    st.title("🛡️ Engenharia de Dados & Segurança: Apache Superset")

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
                    st.write("**Dados Sanitizados (Prontos para o Banco):**")
                    st.json({"dashboard_title": validated_data.get("dashboard_title"), "slug": validated_data.get("slug")})

                    dumped_data = schema.dump(validated_data)
                    st.write("**Payload Final (Verifique a Otimização de Rede/Compressão):**")
                    st.json(dumped_data)

                except ValidationError as err:
                    st.error("❌ Falha na Validação (Bloqueado pela API):")
                    st.json(err.messages)

    # ------------------------------------------
    # ABA 2: FRONTEND DO BANCO DE DADOS
    # ------------------------------------------
    with tab2:
        st.header("Motor de Busca e Gestão de Banco de Dados")
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
                # Tópico 1: Índices e Otimização - Evita Full Table Scan bloqueando buscas amplas
                if not search_term or len(search_term.strip()) < 2:
                    st.error("❌ Tópico 1: Busca bloqueada. Termo muito curto exige full table scan no banco.")
                    return

                def core_query():
                    if usar_cache:
                        return eng.fetch_with_cache(search_term)
                    else:
                        return [c for c in MOCK_DB if search_term in c['slice_name'].lower()]

                st.subheader("Logs do Pipeline de Engenharia")
                
                # Executa a query englobando Retry (5) e Monitoramento (4)
                raw_results = eng.execute_with_retry(
                    lambda: eng.monitor_query(core_query, simular_lentidao),
                    force_fail=simular_falha
                )

                # Aplica Particionamento/Arquivamento (6)
                if filtrar_90_dias or ocultar_arquivados:
                    pre_len = len(raw_results)
                    raw_results = eng.apply_temporal_filter(
                        raw_results, 
                        days_back=90 if filtrar_90_dias else 9999,
                        exclude_archived=ocultar_arquivados
                    )
                    st.info(f"📅 Particionamento/Arquivamento: {pre_len - len(raw_results)} registros antigos ou arquivados foram removidos.")

                # Aplica Data Quality (7)
                if aplicar_dq:
                    raw_results, issues = eng.filter_valid_charts(raw_results)
                    if issues:
                        st.info(f"🧹 Data Quality: {len(issues)} charts corrompidos removidos.")
                        with st.expander("Ver logs de corrupção de dados"): st.json(issues)

                # Aplica Limites de Volume (2)
                final_results = eng.apply_data_limits(raw_results, limite_volume)

                st.subheader(f"Resultado Final ({len(final_results)} registros)")
                
                # Tratamento visual das datas para o JSON final
                display_results = []
                for r in final_results:
                    item = r.copy()
                    if isinstance(item['created_on'], datetime):
                        item['created_on'] = item['created_on'].strftime('%Y-%m-%d')
                    display_results.append(item)
                    
                st.json(display_results)

if __name__ == "__main__":
    main()