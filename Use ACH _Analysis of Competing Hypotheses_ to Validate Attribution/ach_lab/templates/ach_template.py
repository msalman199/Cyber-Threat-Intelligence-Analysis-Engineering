import pandas as pd
import numpy as np

class ACHAnalysis:
    def __init__(self):
        self.hypotheses = []
        self.evidence = []
        self.matrix = None
        
    def add_hypothesis(self, name, description):
        self.hypotheses.append({'name': name, 'description': description})
        
    def add_evidence(self, name, description, reliability):
        self.evidence.append({
            'name': name, 
            'description': description,
            'reliability': reliability
        })
        
    def create_matrix(self):
        rows = len(self.evidence)
        cols = len(self.hypotheses)
        self.matrix = pd.DataFrame(
            index=[e['name'] for e in self.evidence],
            columns=[h['name'] for h in self.hypotheses]
        )
        return self.matrix
        
    def calculate_scores(self):
        if self.matrix is None:
            return None
        
        scores = {}
        for hypothesis in self.matrix.columns:
            # Calculate inconsistency score
            inconsistent = (self.matrix[hypothesis] == '--').sum()
            consistent = (self.matrix[hypothesis] == '++').sum()
            neutral = (self.matrix[hypothesis] == 'N').sum()
            
            # Weight by evidence reliability
            weighted_score = 0
            for idx, evidence in enumerate(self.evidence):
                cell_value = self.matrix.iloc[idx][hypothesis]
                reliability = evidence['reliability']
                
                if cell_value == '++':
                    weighted_score += 2 * reliability
                elif cell_value == '+':
                    weighted_score += 1 * reliability
                elif cell_value == '--':
                    weighted_score -= 2 * reliability
                elif cell_value == '-':
                    weighted_score -= 1 * reliability
                    
            scores[hypothesis] = {
                'inconsistent_count': inconsistent,
                'consistent_count': consistent,
                'weighted_score': weighted_score
            }
            
        return scores
