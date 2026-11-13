# MAGI 6.5.0 R2.1

## Alterações
- Detalhe do ativo: indicadores de serviços, exposições abertas, ataques correlacionados, técnicas executáveis e confiança de fingerprint.
- Backend `get_target`: expõe contagens persistidas; frontend consulta a correlação atual de ataques para atualizar seus indicadores.
- Ícones SVG vetoriais em cards e identificação do ativo, com classificação por tipo, sistema operacional e fabricante.
- Exposições: aba exibe achados abertos, alinhada ao indicador.
- Histórico: apresenta eventos de identidade persistidos e marcos de descoberta.
- Listagem de ativos: sem modificações.
- Não inclui binários do Runner nem repositório externo Atomic Red Team. Rotas e integrações internas mantidas.

## Validação
- `node --check frontend/asset-detail-6.5.js`
- `python -m py_compile backend/app/repositories/target_repository.py`
- Necessária homologação com banco real: comparar indicadores, executar navegação por abas, conferir dados de diferentes tipos de ativos e verificar ausência de regressões.

## Limites
- Confiança representa a confiança da classificação do ativo, não um score de segurança.
- O indicador de ataques representa correlações, não ataques executados.
- Simulações representa técnicas executáveis mapeadas, não execuções comprovadas.
- Ícones são SVG próprios da revisão; conferência visual final contra as referências aprovadas é necessária.
