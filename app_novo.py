import streamlit as st
import json
import time
import re
import unicodedata
import gzip
import base64
import hashlib
import logging
from html import escape
from marshmallow import Schema, fields, validates_schema, ValidationError, pre_load

# Configuração de log
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================================
# 🛡️ PARTE 1: CLASSES DE API E PAYLOADS
# ==========================================
class EnhancedDataValidationMixin:
    @staticmethod
    def validate_slug_format(slug: str) -> bool:
        pattern = r'^[a-z0-9]+(?:-[a-z0-9]+)*$'
        return re.match(pattern, slug.lower()) is not None
    
    @staticmethod
    def validate_json_size(json_str: str, max_size_mb: float = 10.0) -> bool:
        if not json_str: return True
        size_mb = len(json_str.encode('utf-8')) / (1024 * 1024)
        return size_mb <= max_size_mb
    
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
        if errors:
            raise ValidationError(errors)

class DataSanitizationMixin:
    @staticmethod
    def sanitize_html_content(content: str) -> str:
        if not content: return content
        sanitized = escape(content)
        sanitized = ''.join(char for char in sanitized if unicodedata.category(char) != 'Cc')
        return sanitized.strip()
    
    @staticmethod
    def normalize_slug(slug: str) -> str:
        if not slug: return slug
        normalized = unicodedata.normalize('NFKD', slug)
        normalized = normalized.encode('ascii', 'ignore').decode('ascii')
        normalized = re.sub(r'[^\w\s-]', '', normalized).strip().lower()
        normalized = re.sub(r'[-\s]+', '-', normalized)
        return normalized
    
    @pre_load
    def sanitize_inputs(self, data, **kwargs):
        text_fields = ['dashboard_title', 'css', 'certified_by', 'certification_details']
        for field in text_fields:
            if field in data and data[field]:
                data[field] = self.sanitize_html_content(data[field])
        if 'slug' in data and data['slug']:
            data['slug'] = self.normalize_slug(data['slug'])
        return data

class APIDataVolumeControlMixin:
    MAX_CSS_SIZE_KB = 500
    MAX_NESTED_DEPTH = 10
    
    def validate_json_structure(self, json_data: dict, max_depth: int = None) -> dict:
        max_depth = max_depth or self.MAX_NESTED_DEPTH
        def check_depth(obj, current_depth=0):
            if current_depth > max_depth:
                raise ValidationError(f"JSON too deeply nested (max: {max_depth})")
            if isinstance(obj, dict):
                for value in obj.values(): check_depth(value, current_depth + 1)
            elif isinstance(obj, list):
                for item in obj: check_depth(item, current_depth + 1)
        check_depth(json_data)
        return json_data
    
    @validates_schema
    def validate_data_volume(self, data, **kwargs):
        errors = {}
        if 'css' in data and data['css']:
            css_size_kb = len(data['css'].encode('utf-8')) / 1024
            if css_size_kb > self.MAX_CSS_SIZE_KB:
                errors['css'] = [f'CSS exceeds {self.MAX_CSS_SIZE_KB}KB limit']
        if 'position_json' in data and data['position_json']:
            try:
                position_obj = json.loads(data['position_json'])
                self.validate_json_structure(position_obj, max_depth=8)
            except (json.JSONDecodeError, ValidationError) as e:
                errors['position_json'] = [f'Invalid position JSON structure: {str(e)}']
        if errors:
            raise ValidationError(errors)

class CompressedJSONField(fields.Field):
    def __init__(self, compression_threshold=100, **kwargs):
        self.compression_threshold = compression_threshold
        super().__init__(**kwargs)
    
    def _serialize(self, value, attr, obj, **kwargs):
        if not value: return value
        json_str = json.dumps(value) if not isinstance(value, str) else value
        json_bytes = json_str.encode('utf-8')
        if len(json_bytes) > self.compression_threshold:
            compressed = gzip.compress(json_bytes)
            if len(compressed) < len(json_bytes) * 0.8: 
                return {'compressed': True, 'data': base64.b64encode(compressed).decode('ascii')}
        return json_str

class DemoDashboardSchema(Schema, EnhancedDataValidationMixin, DataSanitizationMixin, APIDataVolumeControlMixin):
    dashboard_title = fields.String()
    slug = fields.String()
    published = fields.Boolean()
    css = fields.String()
    position_json = fields.String()
    chart_configuration = CompressedJSONField()


# ==========================================
# 🗄️ PARTE 2: CLASSES DE BANCO DE DADOS E DB MOCK
# ==========================================
MOCK_DB = [
    {"id": i, "slice_name": f"Dashboard {i}", "description": f"Desc {i}", "viz_type": "bar", "datasource_id": 1 if i % 2 == 0 else None, "params": "{}" if i % 3 == 0 else None}
    for i in range(1, 16)
]

class QueryPerformanceMonitor:
    def __init__(self):
        self.slow_query_threshold = 0.5 

    def monitor_query(self, filter_name: str, func, *args, **kwargs):
        start_time = time.time()
        try:
            time.sleep(0.1) 
            return func(*args, **kwargs)
        finally:
            execution_time = time.time() - start_time
            if execution_time > self.slow_query_threshold:
                st.warning(f"⚠️ Slow query detected no filtro '{filter_name}'. Tempo: {execution_time:.4f}s")
            st.info(f"⏱️ Métrica Registrada: '{filter_name}' executado em {execution_time:.4f}s")

class DBDataVolumeControlMixin:
    MAX_RESULTS_DEFAULT = 5  
    MAX_RESULTS_ABSOLUTE = 10 

    def apply_data_limits(self, results: list, limit: int = None) -> list:
        effective_limit = min(limit or self.MAX_RESULTS_DEFAULT, self.MAX_RESULTS_ABSOLUTE)
        result_count = len(results)
        if result_count > effective_limit:
            st.warning(f"⚠️ Volume Control: Retornou {result_count} resultados. Limitando para {effective_limit}.")
        return results[:effective_limit]

class DataQualityMixin:
    def validate_chart_integrity(self, chart: dict) -> dict:
        issues = []
        if not chart.get('datasource_id'):
            issues.append('Datasource missing')
        if not chart.get('params'):
            issues.append('Missing chart configuration')
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'chart_id': chart['id']
        }


# ==========================================
# 🖥️ PARTE 3: INTERFACE PRINCIPAL (STREAMLIT)
# ==========================================
def main():
    st.set_page_config(page_title="Superset Demo", layout="wide")
    st.title("🛡️ Demo Completa: Segurança e Eng. de Dados (Superset)")

    tab1, tab2 = st.tabs(["📝 API: Validação e Payloads", "🗄️ DB: Buscas e Gestão de Dados"])

    # ------------------------------------------
    # ABA 1 - O primeiro formulário de APIs
    # ------------------------------------------
    with tab1:
        st.header("Entrada e Sanitização de Dados")
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
                    st.write("**Dados Sanitizados:**")
                    st.json({"dashboard_title": validated_data.get("dashboard_title"), "slug": validated_data.get("slug")})

                    dumped_data = schema.dump(validated_data)
                    st.write("**Payload Final (Verifique a Compressão):**")
                    st.json(dumped_data)

                except ValidationError as err:
                    st.error("❌ Falha na Validação (ValidationError gerado):")
                    st.json(err.messages)

    # ------------------------------------------
    # ABA 2 - O segundo formulário (Buscas no Banco)
    # ------------------------------------------
    with tab2:
        st.header("Motor de Busca e Gestão de Banco de Dados")
        col_search, col_results = st.columns([1, 2])

        with col_search:
            st.subheader("Filtros de Busca")
            search_term = st.text_input("Buscar Dashboard (Mínimo de 2 caracteres):", "")
            force_slow = st.checkbox("Simular lentidão (Testar Logger)")
            apply_quality = st.checkbox("Aplicar Data Quality (Ocultar dados corrompidos)")
            user_limit = st.number_input("Limite pretendido de resultados:", min_value=1, max_value=20, value=15)
            btn_search = st.button("Executar Query Fictícia")

        with col_results:
            if btn_search:
                monitor = QueryPerformanceMonitor()
                volume_control = DBDataVolumeControlMixin()
                quality_control = DataQualityMixin()

                if force_slow: monitor.slow_query_threshold = 0.0

                if not search_term or len(search_term.strip()) < 2:
                    st.error("❌ A busca foi ignorada: Termo muito curto ou vazio. (Evita sobrecarga no banco)")
                else:
                    def mock_query():
                        sanitized = search_term.strip().lower()
                        return [c for c in MOCK_DB if sanitized in c['slice_name'].lower() or sanitized in c['description'].lower()]
                    
                    raw_results = monitor.monitor_query('chart_all_text', mock_query)

                    if apply_quality:
                        valid_results, quality_logs = [], []
                        for chart in raw_results:
                            val = quality_control.validate_chart_integrity(chart)
                            if val['valid']: valid_results.append(chart)
                            else: quality_logs.append(val)
                        
                        raw_results = valid_results
                        if quality_logs:
                            st.info("🧹 Data Quality Ativado: Alguns charts foram bloqueados.")
                            with st.expander("Ver logs de Data Quality"): st.json(quality_logs)

                    final_results = volume_control.apply_data_limits(raw_results, limit=user_limit)
                    st.subheader(f"Resultados Finais ({len(final_results)})")
                    st.json(final_results)

if __name__ == "__main__":
    main()