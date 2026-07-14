import sys
import json
import os

# Pega o caminho do arquivo SARIF
arquivo_sast = sys.argv[1] if len(sys.argv) > 1 else './output.sarif'

# 1. MAPEAMENTO DA CARTILHA DE QA (MUST HAVE)
cartilha_must_have = {
    "CWE-89": "M-REQ-001 (SQL Injection)",
    "CWE-798": "M-REQ-003 (Credenciais Hardcoded)"
}

if not os.path.exists(arquivo_sast):
    print("::warning::Arquivo SARIF não encontrado.")
    sys.exit(0)

with open(arquivo_sast, 'r') as f:
    sast_data = json.load(f)

violacoes = []
todos_os_cwes_encontrados = set()

# 2. MOTOR DE VALIDAÇÃO COM PRINT DE DEBUG
print("=== DEBUG: Analisando vulnerabilidades do SARIF ===")

for run in sast_data.get('runs', []):
    for result in run.get('results', []):
        rule_id = result.get('ruleId', '')
        tags = result.get('properties', {}).get('tags', [])
        
        # Guarda todos os identificadores encontrados para exibirmos no log
        for tag in tags:
            todos_os_cwes_encontrados.add(tag)
        todos_os_cwes_encontrados.add(rule_id)
        
        # Cruzamento
        for tag in tags + [rule_id]:
            # Normaliza para maiúsculo para evitar problemas de case-sensitive (ex: cwe-89 vs CWE-89)
            tag_upper = str(tag).upper().strip()
            
            if tag_upper in cartilha_must_have:
                req = cartilha_must_have[tag_upper]
                try:
                    local = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
                    linha = result['locations'][0]['physicalLocation']['region']['startLine']
                except:
                    local, linha = "Desconhecido", "?"
                
                msg = f"Falha QA: {req} violado no arquivo {local} (Linha {linha})"
                if msg not in violacoes:
                    violacoes.append(msg)

# Exibe no log tudo o que o scanner achou para sabermos como mapear
print(f"\nIdentificadores/CWEs que o Conviso achou no seu código: {list(todos_os_cwes_encontrados)}")
print("===================================================\n")

# 3. DECISÃO DA PIPELINE
if violacoes:
    for v in violacoes:
        print(f"::error::{v}")
    print("Pipeline bloqueada pelo Quality Gate de Segurança do QA!")
    sys.exit(1)
else:
    print("Validação VRTA: Nenhuma violação dos requisitos mapeados foi encontrada. Passou no Gate!")
    sys.exit(0)