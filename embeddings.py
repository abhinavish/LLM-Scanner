import nltk
from transformers import AutoTokenizer, AutoModel
import torch
import numpy as np

class EmbeddingModel:
    def __init__(self, model_path):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModel.from_pretrained(model_path)

    def create_embedding(self, text):
        raise NotImplementedError("This method should be implemented by subclasses")

class E5EmbeddingModel(EmbeddingModel):
    def __init__(self, model_path):
        super().__init__(model_path)
        # Adding nltk path to load punkt tokenizer
        nltk.data.path.append('/Users/avishnuv/CVELISTV5/nltk_data')

    def create_embedding(self, text, aggregate='mean'):
        # Split text into paragraphs
        paragraphs = text.split('\n\n')
        embeddings = []

        for paragraph in paragraphs:
            # Split paragraph into sentences
            sentences = nltk.sent_tokenize(paragraph)
            for sentence in sentences:
                tokens = self.tokenizer(sentence, return_tensors='pt', padding=True, truncation=True)
                with torch.no_grad():
                    outputs = self.model(**tokens)
                sentence_embedding = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()
                embeddings.append(sentence_embedding)

        # Aggregate embeddings
        if aggregate == 'mean':
            final_embedding = np.mean(embeddings, axis=0)
        elif aggregate == 'max':
            final_embedding = np.max(embeddings, axis=0)
        else:
            raise ValueError(f"Unknown aggregation method: {aggregate}")

        return final_embedding
        
