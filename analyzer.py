
"""
analyzer.py - Analisador com ordenação por tamanho e arquivo de saída
"""

from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
import os
import sys
import argparse
import time
import heapq
from datetime import datetime, timedelta

# ---------- utilitários ----------
def format_size(size_bytes: int) -> str:
    if size_bytes is None or size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    size = float(size_bytes)
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.2f} {units[idx]}"

def format_time(epoch: float) -> str:
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "N/A"

def format_days_ago(epoch: float) -> str:
    """Formata quanto tempo faz desde o último acesso"""
    try:
        days_ago = (time.time() - epoch) / (24 * 3600)
        if days_ago < 1:
            return "<1 dia"
        elif days_ago < 30:
            return f"{int(days_ago)} dias"
        elif days_ago < 365:
            return f"{int(days_ago/30)} meses"
        else:
            return f"{int(days_ago/365)} anos"
    except:
        return "N/A"

def safe_stat(path: str, follow_symlinks: bool = False):
    try:
        return os.stat(path, follow_symlinks=follow_symlinks)
    except (OSError, PermissionError):
        return None

def find_all_files_recursive(root_path: str, follow_symlinks: bool = False, max_files: int = 100000) -> list:
    """Encontra TODOS os arquivos recursivamente a partir do diretório raiz"""
    all_files = []
    try:
        for root, dirs, files in os.walk(root_path, followlinks=follow_symlinks):
            for file in files:
                file_path = os.path.join(root, file)
                all_files.append(file_path)
                if len(all_files) >= max_files:
                    return all_files
    except Exception as e:
        print(f"AVISO: Erro ao caminhar por {root_path}: {e}")
    
    return all_files

def find_all_items_recursive(root_path: str, follow_symlinks: bool = False, max_items: int = 100000) -> list:
    """Encontra TODOS os itens (arquivos e pastas) recursivamente"""
    all_items = []
    try:
        for root, dirs, files in os.walk(root_path, followlinks=follow_symlinks):
            # Adiciona arquivos
            for file in files:
                file_path = os.path.join(root, file)
                all_items.append(file_path)
                if len(all_items) >= max_items:
                    return all_items
            
            # Adiciona pastas (o próprio walk já fornece as pastas)
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                all_items.append(dir_path)
                if len(all_items) >= max_items:
                    return all_items
                    
    except Exception as e:
        print(f"AVISO: Erro ao caminhar por {root_path}: {e}")
    
    return all_items

# ---------- processamento de cada entrada ----------
def process_file_entry(file_path: str, follow_symlinks: bool = False, time_type: str = 'atime') -> tuple:
    """Processa um arquivo individual"""
    try:
        name = os.path.basename(file_path)
        st = safe_stat(file_path, follow_symlinks)
        
        if st is None:
            return 0, name, "Erro", file_path, 0.0, "N/A"
        
        size = st.st_size
        
        if time_type == 'atime':
            time_val = st.st_atime
        elif time_type == 'mtime':
            time_val = st.st_mtime
        else:
            time_val = st.st_ctime
        
        return size, name, "Arquivo", file_path, time_val, format_time(time_val)
        
    except Exception as e:
        return 0, os.path.basename(file_path), "Erro", file_path, 0.0, "N/A"

def process_directory_entry(dir_path: str, follow_symlinks: bool = False, time_type: str = 'atime') -> tuple:
    """Processa um diretório individual"""
    try:
        name = os.path.basename(dir_path)
        st = safe_stat(dir_path, follow_symlinks)
        
        if st is None:
            return 0, name, "Erro", dir_path, 0.0, "N/A"
        
        # Para diretórios, usamos o timestamp do próprio diretório
        if time_type == 'atime':
            time_val = st.st_atime
        elif time_type == 'mtime':
            time_val = st.st_mtime
        else:
            time_val = st.st_ctime
        
        # Tamanho é zero para pastas
        return 0, name, "Pasta", dir_path, time_val, format_time(time_val)
        
    except Exception as e:
        return 0, os.path.basename(dir_path), "Erro", dir_path, 0.0, "N/A"

# ---------- análise principal ----------
def analyze_directory_recursive(
    directory_path: str,
    workers: int = None,
    use_threads: bool = True,
    single_thread: bool = False,
    follow_symlinks: bool = False,
    top_n: int = None,
    min_size: int = 0,
    unused_days: int = None,
    time_type: str = 'atime',
    max_items: int = 100000,
    only_unused: bool = False,
    include_dirs: bool = False,
    output_file: str = None,  # Novo parâmetro para arquivo de saída
):
    """Analisa TODOS os arquivos e pastas"""
    path = os.path.abspath(directory_path)
    
    if not os.path.exists(path):
        print(f"Erro: O caminho '{directory_path}' não existe.")
        return
    
    if not os.path.isdir(path):
        print(f"Erro: '{directory_path}' não é uma pasta.")
        return

    print(f"Analisando: {path}")
    print(f"Buscando TODOS os itens... (limite: {max_items})")
    
    # Encontra TODOS os itens
    if include_dirs:
        all_items = find_all_items_recursive(path, follow_symlinks, max_items)
    else:
        all_items = find_all_files_recursive(path, follow_symlinks, max_items)
    
    total_items = len(all_items)
    
    if total_items == 0:
        print("Nenhum item encontrado!")
        return
    
    print(f"Encontrados: {total_items} itens para análise")
    
    cpu = os.cpu_count() or 1
    if workers is None:
        workers = min(32, cpu * 4)
    workers = max(1, int(workers))

    print(f"Workers: {workers} | Mode: {'single-thread' if single_thread else ('threads' if use_threads else 'processes')}")
    print(f"Time type: {time_type} | min size: {format_size(min_size)}")
    if unused_days:
        print(f"Filtrando itens não usados há >= {unused_days} dias")
    if include_dirs:
        print("Incluindo pastas na análise")
    if output_file:
        print(f"Arquivo de saída: {output_file}")
    print("-" * 120)

    start = time.time()
    results = []
    total_size = 0
    file_count = folder_count = erro_count = 0

    cutoff_epoch = None
    if unused_days is not None:
        cutoff_epoch = time.time() - (unused_days * 24 * 3600)

    # Processamento
    if single_thread:
        for i, item_path in enumerate(all_items, 1):
            print(f"\rProcessando {i}/{total_items}...", end="", flush=True)
            
            if os.path.isfile(item_path):
                result = process_file_entry(item_path, follow_symlinks, time_type)
            else:
                if not include_dirs:
                    continue
                result = process_directory_entry(item_path, follow_symlinks, time_type)
            
            size, name, typ, fullpath, time_val, time_str = result
            
            # Aplicar filtros
            if size < min_size:
                continue
            if cutoff_epoch is not None and time_val >= cutoff_epoch and only_unused:
                continue
                
            results.append(result)
            total_size += size
            
            if typ == "Arquivo":
                file_count += 1
            elif typ == "Pasta":
                folder_count += 1
            elif typ == "Erro":
                erro_count += 1
                
    else:
        Executor = ThreadPoolExecutor if use_threads else ProcessPoolExecutor
        with Executor(max_workers=workers) as ex:
            # Prepara as tarefas
            futures = []
            for item_path in all_items:
                if os.path.isfile(item_path):
                    futures.append(ex.submit(process_file_entry, item_path, follow_symlinks, time_type))
                else:
                    if include_dirs:
                        futures.append(ex.submit(process_directory_entry, item_path, follow_symlinks, time_type))
                    else:
                        continue
            
            processed = 0
            total_futures = len(futures)
            
            for fut in as_completed(futures):
                processed += 1
                try:
                    result = fut.result()
                except Exception:
                    result = (0, "?", "Erro", "?", 0.0, "N/A")
                
                size, name, typ, fullpath, time_val, time_str = result
                
                # Filtros
                if size < min_size:
                    continue
                if cutoff_epoch is not None and time_val >= cutoff_epoch and only_unused:
                    continue
                    
                results.append(result)
                total_size += size
                
                if typ == "Arquivo":
                    file_count += 1
                elif typ == "Pasta":
                    folder_count += 1
                elif typ == "Erro":
                    erro_count += 1
                
                print(f"\rProcessados: {processed}/{total_futures} | Coletados: {len(results)} | Tamanho: {format_size(total_size)}", end="", flush=True)

    elapsed = time.time() - start
    print(f"\rProcessamento concluído em {elapsed:.2f} segundos")
    print("-" * 120)

    # ORDENAÇÃO POR TAMANHO (MAIOR PARA MENOR)
    items_sorted = sorted(results, key=lambda x: x[0], reverse=True)
    
    if top_n and top_n > 0:
        items_sorted = items_sorted[:top_n]

    # Prepara conteúdo para arquivo de saída
    output_content = []
    
    # Cabeçalho do arquivo
    output_content.append(f"Análise de: {path}")
    output_content.append(f"Data da análise: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output_content.append(f"Total de itens analisados: {len(all_items)}")
    output_content.append(f"Total de itens filtrados: {len(results)}")
    output_content.append(f"Tamanho total: {format_size(total_size)}")
    output_content.append(f"Tempo de processamento: {elapsed:.2f} segundos")
    output_content.append("=" * 120)
    output_content.append(f"{'NOME':<40} {'TIPO':<8} {'TAMANHO':>12} {'ÚLTIMO USO':>20} {'DIAS':>8} {'CAMINHO COMPLETO'}")
    output_content.append("=" * 120)
    
    # Adiciona cada item ao conteúdo
    for size, name, typ, fullpath, time_val, time_str in items_sorted:
        name_display = (name[:37] + "...") if len(name) > 40 else name
        size_display = format_size(size)
        time_display = time_str if time_str else "N/A"
        days_ago = format_days_ago(time_val)
        
        output_content.append(f"{name_display:<40} {typ:<8} {size_display:>12} {time_display:>20} {days_ago:>8} {fullpath}")
    
    output_content.append("=" * 120)
    output_content.append(f"Total: {len(results)} itens ({file_count} arquivos, {folder_count} pastas, {erro_count} erros)")

    # Salva em arquivo se especificado
    if output_file:
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(output_content))
            print(f"Arquivo de saída salvo: {output_file}")
        except Exception as e:
            print(f"Erro ao salvar arquivo: {e}")

    # Exibe no console (apenas resumo)
    print(f"\n{'NOME':<40} {'TIPO':<8} {'TAMANHO':>12} {'ÚLTIMO USO':>20} {'DIAS':>8} {'CAMINHO'}")
    print("-" * 120)
    
    # Mostra apenas os top 20 no console para não poluir
    display_count = min(20, len(items_sorted))
    for i, (size, name, typ, fullpath, time_val, time_str) in enumerate(items_sorted[:display_count]):
        name_display = (name[:37] + "...") if len(name) > 40 else name
        size_display = format_size(size)
        time_display = time_str if time_str else "N/A"
        days_ago = format_days_ago(time_val)
        
        # Mostra caminho relativo para melhor legibilidade no console
        rel_path = os.path.relpath(fullpath, path)
        if len(rel_path) > 50:
            rel_path = "..." + rel_path[-47:]
        
        print(f"{name_display:<40} {typ:<8} {size_display:>12} {time_display:>20} {days_ago:>8} {rel_path}")
    
    if len(items_sorted) > display_count:
        print(f"... e mais {len(items_sorted) - display_count} itens (ver arquivo de saída para lista completa)")
    
    print("-" * 120)
    print(f"Total analisado: {len(all_items)} itens")
    print(f"Total filtrado: {len(results)} itens ({file_count} arquivos, {folder_count} pastas, {erro_count} erros)")
    print(f"Tamanho total: {format_size(total_size)}")
    print(f"Tempo total: {elapsed:.2f} segundos")
    
    # Estatísticas dos maiores arquivos
    if results:
        top_5 = items_sorted[:5]
        print(f"\nTOP 5 MAIORES ARQUIVOS:")
        for i, (size, name, typ, fullpath, time_val, time_str) in enumerate(top_5, 1):
            if typ == "Arquivo":
                print(f"{i}. {format_size(size):>10} - {name}")

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Analisa os arquivos ordenados por tamanho")
    p.add_argument("directory", nargs="?", default=".", help="Diretório a analisar (padrão: atual)")
    p.add_argument("-w", "--workers", type=int, help="Número de workers (threads/processos).")
    p.add_argument("--no-threads", action="store_true", help="Usar processos em vez de threads.")
    p.add_argument("--single", action="store_true", help="Modo single-thread.")
    p.add_argument("--follow-symlinks", action="store_true", help="Seguir symlinks.")
    p.add_argument("--top", type=int, help="Mostrar apenas os top N itens maiores.")
    p.add_argument("--min-size", type=int, default=0, help="Ignorar itens com tamanho menor que X bytes.")
    p.add_argument("--unused-days", type=int, help="Filtrar itens não usados há pelo menos N dias.")
    p.add_argument("--time-type", choices=['atime','mtime','ctime'], default='atime', help="Timestamp a usar para definir 'uso'.")
    p.add_argument("--max-items", type=int, default=100000, help="Limite máximo de itens a analisar.")
    p.add_argument("--only-unused", action="store_true", help="Mostrar apenas itens não usados.")
    p.add_argument("--include-dirs", action="store_true", help="Incluir pastas na análise (além de arquivos).")
    p.add_argument("-o", "--output", type=str, help="Arquivo de saída para salvar resultados completos.")
    
    return p.parse_args()

def main():
    args = parse_args()
    
    analyze_directory_recursive(
        args.directory,
        workers=args.workers,
        use_threads=not args.no_threads,
        single_thread=args.single,
        follow_symlinks=args.follow_symlinks,
        top_n=args.top,
        min_size=args.min_size,
        unused_days=args.unused_days,
        time_type=args.time_type,
        max_items=args.max_items,
        only_unused=args.only_unused,
        include_dirs=args.include_dirs,
        output_file=args.output,
    )
    
    try:
        input("\nPressione Enter para finalizar... ")
    except EOFError:
        pass

if __name__ == "__main__":
    if sys.platform.startswith('win'):
        from multiprocessing import freeze_support
        freeze_support()
    main()
