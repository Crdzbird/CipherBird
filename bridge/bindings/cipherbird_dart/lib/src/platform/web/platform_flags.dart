part of 'web_platform.dart';

/// True: this is the browser layer.
const bool platformIsWeb = true;

/// True when the engine runs in the worker only; see `preload`.
bool get engineWorkerOnly => WebEngine.workerOnly;
