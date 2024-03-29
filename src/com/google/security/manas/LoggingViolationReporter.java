/*
 * Copyright (C) 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.security.manas;

import com.google.common.base.Preconditions;

import java.security.Permission;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Logs security policy violations along with full stacktrace.
 * 
 * @author Meder Kydyraliev
 */
public class LoggingViolationReporter implements com.google.security.manas.SecurityViolationReporter {
  private static final Logger logger = Logger.getLogger(LoggingViolationReporter.class.getName());
  
  @Override
  public void reportViolation(Permission permission) {
    Preconditions.checkNotNull(permission);
    logger.log(Level.SEVERE, "Security policy violation: " + permission, new Throwable());
  }
}
