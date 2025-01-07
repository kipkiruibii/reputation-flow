import pinecone
import openai
import numpy as np
from django.conf import settings
from pinecone import Pinecone, ServerlessSpec

# Initialize Pinecone
pc = Pinecone(
    api_key=settings.PINECONE_API_KEY,  
)
# Initialize OpenAI
openai.api_key = settings.OPENAI_API_KEY

# Index name
index_name = "knowledge-base"

# Check if the index exists
if index_name not in pc.list_indexes().names():
    pass

# Access the index
index = pc.Index(host=settings.PINECONE_HOST)

# Function to generate embeddings
def generate_embeddings(text):
    try:
        response = openai.Embedding.create(
            input=text,
            model="text-embedding-ada-002"
        )
        return response["data"][0]["embedding"]
    except Exception as e:
        print(f"Error generating embedding: {e}")
        return None

# Function to upsert vectors into Pinecone with company_id in metadata
def upsert_vectors(doc_id, text_chunks, company_id):
    vectors = []
    for i, chunk in enumerate(text_chunks):
        embedding = generate_embeddings(chunk)
        if embedding:
            vector_id = f"{doc_id}_{i}"  # Unique ID for each chunk
            metadata = {
                "text": chunk,
                "company_id": company_id  # Include company_id in metadata
            }
            vectors.append((vector_id, embedding, metadata))

    if vectors:
        index.upsert(vectors)  # Upsert the vectors into Pinecone
        print(f"Upserted {len(vectors)} vectors.")
    else:
        print("No vectors to upsert.")
        
def query_knowledge_base(query, top_k=5):
    query_embedding = generate_embeddings(query)
    results = index.query(vector=query_embedding, top_k=top_k, include_metadata=True)
    return [(res["metadata"]["text"], res["score"]) for res in results["matches"]]

