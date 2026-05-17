import streamlit as st
import json
import time
import re
import unicodedata
import gzip
import base64
import hashlib
import pickle
import logging
from html import escape
from functools import lru_cache
from marshmallow import Schema, fields, validates_schema, ValidationError, post_load

# Configuração de log
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==========================================
# 1. SUAS CLASSES E MIXINS (Coladas aqui)
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
    
    @post_load
    def sanitize_inputs(self, data, **kwargs):
        text_fields = ['dashboard_title', 'css', 'certified_by', 'certification_details']
        for field in text_fields:
            if field in data and data[field]:
                data[field] = self.sanitize_html_content(data[field])
        if 'slug' in data and data['slug']:
            data['slug'] = self.normalize_slug(data['slug'])
        return data

class DataVolumeControlMixin:
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
    def __init__(self, compression_threshold=100, **kwargs): # Reduzido para testar na UI
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

# ==========================================
# 2. DEFINIÇÃO DO SCHEMA DE TESTE
# ==========================================
class DemoDashboardSchema(Schema, EnhancedDataValidationMixin, DataSanitizationMixin, DataVolumeControlMixin):
    dashboard_title = fields.String()
    slug = fields.String()
    published = fields.Boolean()
    css = fields.String()
    position_json = fields.String()
    chart_configuration = CompressedJSONField()

# ==========================================
# 3. INTERFACE DO STREAMLIT
# ==========================================
def main():
    st.set_page_config(page_title="Superset Data Validation Demo", layout="wide")
    st.title("🛡️ Demo: Validação e Otimização do Apache Superset")
    st.markdown("Teste em tempo real os Mixins de validação, sanitização, controle de volume e compressão.")

    schema = DemoDashboardSchema()

    # Layout em duas colunas: Inputs (Esquerda) e Resultados (Direita)
    col1, col2 = st.columns(2)

    with col1:
        st.header("Entrada de Dados")
        with st.form("demo_form"):
            dashboard_title = st.text_input("Dashboard Title (Tente usar tags HTML <script>alert(1)</script>)")
            slug = st.text_input("Slug (Tente usar espaços ou caracteres especiais como 'Meu Slug Inválido @!')")
            published = st.checkbox("Publicado (Se marcado, exige título)")
            css = st.text_area("CSS Customizado")
            position_json = st.text_area("Position JSON (Tente criar um JSON com aninhamento > 8 para simular erro de volume)", '{"row1": {"col1": "chart1"}}')
            chart_config = st.text_area("Chart Configuration JSON (Crie um JSON grande para testar a compressão)", '{"filters": ["long_string_to_force_compression_threshold_' * 10 + '"]}')
            
            submit = st.form_submit_button("Processar Dados")

    with col2:
        st.header("Processamento e Resultados")
        if submit:
            # Construindo o payload de entrada
            raw_data = {
                "dashboard_title": dashboard_title,
                "slug": slug,
                "published": published,
                "css": css,
                "position_json": position_json,
            }
            
            # Tratando o JSON Field antes de validar
            try:
                if chart_config:
                    raw_data["chart_configuration"] = json.loads(chart_config)
            except json.JSONDecodeError:
                st.error("❌ Erro de Sintaxe: O Chart Configuration não é um JSON válido.")
                return

            st.subheader("1. Logs de Validação e Sanitização")
            try:
                # O Marshmallow load dispara os validates_schema e post_load
                validated_data = schema.load(raw_data)
                st.success("✅ Validação e Sanitização passaram com sucesso!")
                
                # Exibe como os dados ficaram após o DataSanitizationMixin
                st.write("**Dados Sanitizados (Inputs Normalizados):**")
                st.json({
                    "dashboard_title": validated_data.get("dashboard_title"),
                    "slug": validated_data.get("slug")
                })

                st.subheader("2. Compressão de Payloads (Dump)")
                # O Marshmallow dump dispara o _serialize do CompressedJSONField
                dumped_data = schema.dump(validated_data)
                
                st.write("**Payload Final (Verifique a Compressão do JSON):**")
                st.json(dumped_data)
                
                # Feedback específico sobre compressão
                chart_out = dumped_data.get("chart_configuration")
                if isinstance(chart_out, dict) and chart_out.get("compressed"):
                    st.info("📉 O Chart Configuration ultrapassou o threshold e foi **comprimido com sucesso** via gzip e encodado em base64!")
                else:
                    st.warning("O Chart Configuration permaneceu em texto plano (não superou o tamanho necessário para compressão).")

            except ValidationError as err:
                # Captura os erros gerados pelo EnhancedDataValidationMixin e DataVolumeControlMixin
                st.error("❌ Falha na Validação (ValidationError gerado):")
                st.json(err.messages)

if __name__ == "__main__":
    main()