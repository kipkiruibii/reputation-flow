import pinecone
import openai
import numpy as np
from django.conf import settings
from pinecone import Pinecone, ServerlessSpec
from openai import OpenAI
from.models import CompanyKnowledgeBase,Company
import traceback

# Initialize Pinecone
pc = Pinecone(
    api_key=settings.PINECONE_API_KEY,  
)
# Initialize OpenAI
# openai.api_key = settings.OPENAI_API_KEY
oai_client = OpenAI(api_key=settings.OPENAI_API_KEY)

# Index name
index_name = "knowledge-base"

# Check if the index exists
if index_name not in pc.list_indexes().names():
    pass

# Access the index
index = pc.Index(host=settings.PINECONE_HOST)

# Function to generate embeddings
def generate_embeddings(text):
    # try:
        # response = openai.Embedding.create(
        #     input=text,
        #     model="text-embedding-ada-002"
        # )
    response = oai_client.embeddings.create(
        model="text-embedding-ada-002",
        input=text
    )
    return response.data[0].embedding
    # except Exception as e:
    #     print(f"Error generating embedding: {e}")
    #     return None

# Function to upsert vectors into Pinecone with company_id in metadata
def upsert_vectors(doc_id, text_chunks, company_id):
    vectors = []
    chunks=0
    for i, chunk in enumerate(text_chunks):
        chunks+=1
        embedding = generate_embeddings(chunk)
        if embedding:
            vector_id = f"{doc_id}_{i}"  # Unique ID for each chunk
            metadata = {
                "text": chunk,
                "company_id": company_id  # Include company_id in metadata
            }
            vectors.append((vector_id, embedding, metadata))
    cp=Company.objects.filter(company_id=company_id).first()
    if cp:
        ckb=CompanyKnowledgeBase.objects.filter(company=cp)
        for ck in ckb:
            if ck.file.name == doc_id:
                ck.chunk_size=chunks
                ck.save()
    if vectors:
        index.upsert(vectors)  # Upsert the vectors into Pinecone
        print(f"Upserted {len(vectors)} vectors.")
    else:
        print("No vectors to upsert.")
        
def query_knowledge_base(query, top_k=5):
    query_embedding = generate_embeddings(query)
    results = index.query(vector=query_embedding, top_k=top_k, include_metadata=True)
    return [(res["metadata"]["text"], res["score"]) for res in results["matches"]]

def delete_vectors(doc_id, total_chunks):
    try:
        # Generate vector IDs for all chunks of the document
        vector_ids = [f"{doc_id}_{i}" for i in range(total_chunks)]
        # Delete vectors from Pinecone
        index.delete(ids=vector_ids)
        print(f"Successfully deleted {len(vector_ids)} vectors associated with {doc_id}.")
    
    except Exception as e:
        print(f"Error deleting vectors: {e} {traceback.format_exc()}")
