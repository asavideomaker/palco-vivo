# Modelo de voz do Stagebook

`voz.onnx` reconhece quem está falando no modo Reunião. Roda no navegador de quem usa; o som não sai do computador.

- Origem: WeSpeaker ResNet34 treinado na VoxCeleb (projeto WeSpeaker, licença Apache-2.0; dados VoxCeleb, CC BY 4.0), na versão ONNX publicada pelo projeto sherpa-onnx (k2-fsa).
- Reduzido para 8 bits (de 26 MB para 7 MB), sem perda perceptível nos testes.
- Entrada: 80 faixas de fbank (Kaldi), 16 kHz, com a média de cada faixa subtraída. Saída: impressão de voz com 256 números.
