# What is AI BOM?

An AI-BOM is a machine-readable inventory of every component an AI system depends on models, training datasets, frameworks, prompts, agents and provenance information, recorded in enough detail to identify and audit each one. It is the AI equivalent of an SBOM.

## How is AI-BOM different from SBOM?

An SBOM lists software components such as libraries and packages. An AI-BOM extends that concept to cover AI elements, foundation models, datasets, embeddings and model lineage, that a conventional SBOM was never designed to capture. AI-BOMs complement, rather than replace, SBOMs.

## Is AI-BOM replacement of SBOM?

An AI-BOM does not replace the SBOM.

For years, SBOMs have helped organizations understand which software components sit inside their products, enabling vulnerability management,  license compliance, and supply chain transparency. But AI systems introduce layers that traditional SBOMs were never designed to capture. 

Modern AI solutions depend not only on software libraries and packages, but also on foundation models, training and fine-tuning datasets, prompts, agents, evaluation artefacts, provenance information and a complex set of licensing and copyright obligations. An AI-BOM does not replace the SBOM, it extends it, documenting the AI-specific elements that a conventional SBOM misses: 

Foundation models and Large Language Models (LLMs) 
Training and fine-tuning datasets, with data provenance 
AI frameworks and libraries 
Agents, prompts and embeddings 
Evaluation and testing artefacts 
Model provenance and lineage 
Licensing, copyright and governance information

## What formats are used for AI-BOMs?

The two leading formats are CycloneDX and SPDX, both of which can already carry AI-specific components alongside traditional software dependencies. 

## AI should be treated as another supply-chain input

Just as organizations maintain inventories of software libraries and third-party components, they now need visibility into which AI models are used, which datasets contributed to those models, where AI-generated code is entering the codebase, what licensing obligations apply and what human reviews have been performed. This shifts the focus from dependency scanning alone to comprehensive AI supply chain security and governance. 

