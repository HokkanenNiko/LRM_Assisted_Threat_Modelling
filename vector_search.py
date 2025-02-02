import os
import xml.etree.ElementTree as ET
import numpy as np
import faiss
from sentence_transformers import SentenceTransformer

def initialize_vector_database_with_chunks(chunks):
    vector_search = XMLVectorSearch()

    print(f"Adding {len(chunks)} chunks to the vector database...")
    vector_search.add_to_index(chunks)
    return vector_search

def add_to_vector_database(vector_search, chunks):
    print(f"Adding {len(chunks)} chunks to the vector database...")
    vector_search.add_to_index(chunks)
    return vector_search

def initialize_vector_database(context):
    vector_search = XMLVectorSearch()

    # Step 1: Chunk the context
    print("Chunking the context...")
    chunks = chunk_text(context, chunk_size=100, chunk_overlap=20)

    # Step 2: Add chunks to the vector database
    print(f"Adding {len(chunks)} chunks to the vector database...")
    vector_search.add_to_index(chunks)
    return vector_search

def chunk_text(
    text: str,
    chunk_size: int = 500,
    chunk_overlap: int = 50
) -> list[str]:
    """
    Break text into chunks of `chunk_size` tokens (approx),
    overlapping by `chunk_overlap` tokens where possible.
    
    Args:
        text (str): The input text to chunk.
        chunk_size (int): Target size of each chunk.
        chunk_overlap (int): Overlap between consecutive chunks.
    
    Returns:
        list[str]: List of chunked text segments.
    """
    # Split by whitespace for a simple token approximation
    words = text.split()

    chunks = []
    start = 0

    while start < len(words):
        # End index for this chunk
        end = start + chunk_size

        # Create the chunk by slicing the list of words
        chunk_words = words[start:end]
        chunk_str = " ".join(chunk_words).strip()
        chunks.append(chunk_str)

        # Move the start index, factoring in overlap
        start = end - chunk_overlap
    
    # Filter out empty chunks if any
    chunks = [c for c in chunks if c.strip()]
    return chunks

class XMLVectorSearch:
    def __init__(self, embedding_model='all-MiniLM-L6-v2', dimension=384):
        """
        Initialize the XML Vector Search class.
        :param embedding_model: Pre-trained SentenceTransformer model for embedding generation.
        :param dimension: Dimensionality of the embeddings (default is 384 for MiniLM).
        """
        self.model = SentenceTransformer(embedding_model)
        self.dimension = dimension
        self.index = faiss.IndexFlatL2(self.dimension)  # FAISS index for L2 distance
        self.metadata = []  # Store metadata for each embedding

    def generate_embeddings(self, chunks):
        """
        Generate embeddings for a list of text chunks.
        :param chunks: List of text chunks.
        :return: List of embeddings.
        """
        return self.model.encode(chunks, convert_to_tensor=False)

    def add_to_index(self, chunks):
        """
        Add chunks to the vector database.
        :param chunks: List of text chunks.
        """
        embeddings = self.generate_embeddings(chunks)
        self.index.add(np.array(embeddings, dtype='float32'))

        # Add metadata for each chunk
        for i, chunk in enumerate(chunks):
            self.metadata.append({
                "id": f"chunk_{len(self.metadata) + i + 1}",
                "text": chunk
            })

    def search(self, query, top_k=5):
        """
        Perform a semantic search on the vector database.
        :param query: Search query as a string.
        :param top_k: Number of top results to retrieve.
        :return: List of top-k results with metadata.
        """
        # Generate embedding for the query
        query_embedding = self.model.encode([query], convert_to_tensor=False)
        query_embedding = np.array(query_embedding, dtype='float32')

        # Perform the search
        distances, indices = self.index.search(query_embedding, top_k)

        # Retrieve metadata for results
        results = []
        for idx in indices[0]:
            if idx < len(self.metadata):
                results.append(self.metadata[idx])

        return results
