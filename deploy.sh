#!/bin/bash

echo "🚀 Building and deploying site..."

# Build the site
echo "📦 Installing dependencies..."
bun install

echo "🔨 Building with Astro..."
bun run build

if [ $? -eq 0 ]; then
    echo "✅ Build successful!"
    
    # Add the built dist folder to git
    echo "📁 Adding built artifacts to git..."
    git add dist/
    
    # Commit the built artifacts
    echo "💾 Committing built artifacts..."
    git commit -m "Build site for deployment [auto-generated]"
    
    # Push to trigger deployment
    echo "🚀 Pushing to trigger deployment..."
    git push origin main
    
    echo "🎉 Deployment triggered! Check GitHub Actions for status."
else
    echo "❌ Build failed! Aborting deployment."
    exit 1
fi
