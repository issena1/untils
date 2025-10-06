from random import randint, shuffle

class Sudoku:
    def __init__(self):
        self.matriz = []
        self.gera_matriz()

    def gera_matriz(self):
        self.matriz = []
        for i in range(0, 9):
            self.matriz.append([])
            for j in range(0, 9):
                self.matriz[i].append(0)

    def mostra_matriz(self):
        print("+" + "---+" * 9)
        for i, linha in enumerate(self.matriz):
            print("|", end="")
            for j, num in enumerate(linha):
                if num == 0:
                    print("   |", end="")
                else:
                    print(f" {num} |", end="")
            print()
            print("+" + "---+" * 9)

    def cria_sudoku_exemplo(self):
        self.matriz = [
            [6, 0, 0, 8, 2, 7, 5, 0, 9],
            [2, 5, 0, 0, 4, 0, 0, 3, 0],
            [0, 8, 0, 0, 0, 1, 0, 7, 2],
            [0, 0, 2, 4, 0, 0, 0, 0, 7],
            [0, 0, 6, 7, 5, 0, 0, 8, 0],
            [7, 4, 5, 2, 1, 0, 0, 0, 0],
            [5, 6, 1, 0, 7, 0, 9, 2, 8],
            [4, 0, 0, 0, 0, 0, 0, 0, 3],
            [0, 0, 0, 9, 0, 2, 0, 1, 0]
        ]

    def verifica_linhas(self):
        for linha in self.matriz:
            numeros = []
            for k in linha:
                if k != 0:
                    if k in numeros:
                        return False
                    else:
                        numeros.append(k)
        return True

    def verifica_colunas(self):
        for i in range(9):
            numeros = []
            for j in range(9):
                k = self.matriz[j][i]
                if k != 0:
                    if k in numeros:
                        return False
                    else:
                        numeros.append(k)
        return True

    def verifica_submatrizes(self):
        for i in range(3):
            for j in range(3):
                numeros = []
                for k in range(3):
                    for l in range(3):
                        m = self.matriz[i*3+k][j*3+l]
                        if m != 0:
                            if m in numeros:
                                return False
                            else:
                                numeros.append(m)
        return True

    def verifica_sudoku(self):
        return self.verifica_linhas() and self.verifica_colunas() and self.verifica_submatrizes()

    def eh_valido(self, linha, coluna, numero):
        # Verifica se o número pode ser colocado na posição
        # Verifica linha
        for i in range(9):
            if self.matriz[linha][i] == numero:
                return False
        
        # Verifica coluna
        for i in range(9):
            if self.matriz[i][coluna] == numero:
                return False
        
        # Verifica submatriz 3x3
        inicio_linha = (linha // 3) * 3
        inicio_coluna = (coluna // 3) * 3
        for i in range(3):
            for j in range(3):
                if self.matriz[inicio_linha + i][inicio_coluna + j] == numero:
                    return False
        
        return True

    def resolve_sudoku(self):
        # Encontra próxima célula vazia
        for i in range(9):
            for j in range(9):
                if self.matriz[i][j] == 0:
                    # Tenta todos os números possíveis
                    for num in range(1, 10):
                        if self.eh_valido(i, j, num):
                            self.matriz[i][j] = num
                            if self.resolve_sudoku():
                                return True
                            self.matriz[i][j] = 0  # Backtrack
                    return False
        return True

    def gera_sudoku_completo(self):
        # Gera um sudoku completo válido
        self.gera_matriz()
        
        # Preenche a diagonal principal com números aleatórios
        for i in range(0, 9, 3):
            numeros = list(range(1, 10))
            shuffle(numeros)
            for j in range(3):
                for k in range(3):
                    self.matriz[i+j][i+k] = numeros.pop()
        
        # Resolve o resto do sudoku
        self.resolve_sudoku()

    def gera_sudoku_facil(self, celulas_vazias=35):
        # Gera um sudoku completo e depois remove algumas células
        self.gera_sudoku_completo()
        
        # Remove células para criar o puzzle
        celulas_removidas = 0
        tentativas = 0
        
        while celulas_removidas < celulas_vazias and tentativas < 100:
            i = randint(0, 8)
            j = randint(0, 8)
            
            if self.matriz[i][j] != 0:
                valor_backup = self.matriz[i][j]
                self.matriz[i][j] = 0
                
                # Verifica se ainda tem solução única
                temp_matriz = [linha[:] for linha in self.matriz]
                solucoes = self.conta_solucoes()
                self.matriz = temp_matriz
                
                if solucoes == 1:
                    celulas_removidas += 1
                else:
                    self.matriz[i][j] = valor_backup
                
                tentativas += 1

    def conta_solucoes(self):
        # Conta quantas soluções existem para o sudoku atual
        count = 0
        
        def backtrack():
            nonlocal count
            if count > 1:  # Para se já tiver mais de uma solução
                return
            
            for i in range(9):
                for j in range(9):
                    if self.matriz[i][j] == 0:
                        for num in range(1, 10):
                            if self.eh_valido(i, j, num):
                                self.matriz[i][j] = num
                                backtrack()
                                self.matriz[i][j] = 0
                        return
            
            count += 1
        
        backtrack()
        return count

    def gera_sudoku_dificil(self, celulas_vazias=45):
        self.gera_sudoku_facil(celulas_vazias)

if __name__ == "__main__":
    sudoku = Sudoku()
    
    print("Sudoku exemplo:")
    sudoku.cria_sudoku_exemplo()
    sudoku.mostra_matriz()
    print("Válido:", sudoku.verifica_sudoku())
    print()
    
    print("Sudoku fácil gerado:")
    sudoku.gera_sudoku_facil()
    sudoku.mostra_matriz()
    print("Válido:", sudoku.verifica_sudoku())
    print()
    
    print("Resolvendo o sudoku fácil:")
    temp = Sudoku()
    temp.matriz = [linha[:] for linha in sudoku.matriz]  # Copia
    temp.resolve_sudoku()
    temp.mostra_matriz()